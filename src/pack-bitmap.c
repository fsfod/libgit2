#include "git2.h"
#include "cache.h"
#include "commit.h"
#include "tag.h"
#include "diff.h"
//#include "revision.h"
//#include "progress.h"
//#include "list-objects.h"
#include "pack.h"
#include "pack-bitmap.h"
//#include "pack-revindex.h"
#include "pack-objects.h"
#include "util.h"
#include "object.h"
//#include "packfile.h"

/*
 * An entry on the bitmap index, representing the bitmap for a given
 * commit.
 */
struct stored_bitmap {
	git_oid sha1;
	struct ewah_bitmap *root;
	struct stored_bitmap *xor;
	int flags;
};

#define TYPE_BITS   3
/*
* object flag allocation:
* revision.h:      0---------10                                26
* fetch-pack.c:    0---5
* walker.c:        0-2
* upload-pack.c:       4       11----------------19
* builtin/blame.c:               12-13
* bisect.c:                               16
* bundle.c:                               16
* http-push.c:                            16-----19
* commit.c:                               16-----19
* sha1_name.c:                                     20
* list-objects-filter.c:                             21
* builtin/fsck.c:  0--3
*/
#define FLAG_BITS  27

struct object {
  unsigned parsed : 1;
  unsigned type : TYPE_BITS;
  unsigned flags : FLAG_BITS;
  git_oid oid;
};

/*
 * The currently active bitmap index. By design, repositories only have
 * a single bitmap index available (the index for the biggest packfile in
 * the repository), since bitmap indexes need full closure.
 *
 * If there is more than one bitmap index available (e.g. because of alternates),
 * the active bitmap index is the largest one.
 */
static struct bitmap_index {
	/* Packfile to which this bitmap index belongs to */
	struct git_pack_file *pack;

	/*
	 * Mark the first `reuse_objects` in the packfile as reused:
	 * they will be sent as-is without using them for repacking
	 * calculations
	 */
	uint32_t reuse_objects;

	/* mmapped buffer of the whole bitmap index */
	unsigned char *map;
	size_t map_size; /* size of the mmaped buffer */
	size_t map_pos; /* current position when loading the index */

	/*
	 * Type indexes.
	 *
	 * Each bitmap marks which objects in the packfile  are of the given
	 * type. This provides type information when yielding the objects from
	 * the packfile during a walk, which allows for better delta bases.
	 */
	struct ewah_bitmap *commits;
	struct ewah_bitmap *trees;
	struct ewah_bitmap *blobs;
	struct ewah_bitmap *tags;

	/* Map from SHA1 -> `stored_bitmap` for all the bitmapped commits */
	khash_sha1 *bitmaps;

	/* Number of bitmapped commits */
	uint32_t entry_count;

	/* Name-hash cache (or NULL if not present). */
	uint32_t *hashes;

	/*
	 * Extended index.
	 *
	 * When trying to perform bitmap operations with objects that are not
	 * packed in `pack`, these objects are added to this "fake index" and
	 * are assumed to appear at the end of the packfile for all operations
	 */
	struct eindex {
		struct object **objects;
		uint32_t *hashes;
		uint32_t count, alloc;
		khash_sha1_pos *positions;
	} ext_index;

	/* Bitmap result of the last performed walk */
	struct bitmap *result;

	/* Version of the bitmap index */
	unsigned int version;

	unsigned loaded : 1;

} bitmap_git;

static struct ewah_bitmap *lookup_stored_bitmap(struct stored_bitmap *st)
{
	struct ewah_bitmap *parent;
	struct ewah_bitmap *composed;

	if (st->xor == NULL)
		return st->root;

	composed = ewah_pool_new();
	parent = lookup_stored_bitmap(st->xor);
	ewah_xor(st->root, parent, composed);

	ewah_pool_free(st->root);
	st->root = composed;
	st->xor = NULL;

	return composed;
}

/*
 * Read a bitmap from the current read position on the mmaped
 * index, and increase the read position accordingly
 */
int read_bitmap_1(struct bitmap_index *index, struct ewah_bitmap **bitmap)
{
	struct ewah_bitmap *b = ewah_pool_new();

	int bitmap_size = ewah_read_mmap(b,
		index->map + index->map_pos,
		index->map_size - index->map_pos);

	if (bitmap_size < 0) {
	  giterr_set(GITERR_INVALID, "Failed to load bitmap index (corrupted?)");
	  ewah_pool_free(b);
	  return -1;
	}

	index->map_pos += bitmap_size;
	*bitmap = b;
	return 0;
}

static int load_bitmap_header(struct git_pack_file *p, struct bitmap_index *index)
{
	struct bitmap_disk_header *header = (void *)index->map;

	if (index->map_size < sizeof(*header) + 20) {
	  giterr_set(GITERR_INVALID, "Corrupted bitmap index (missing header data)");
	  return -1;
	}

	if (memcmp(header->magic, BITMAP_IDX_SIGNATURE, sizeof(BITMAP_IDX_SIGNATURE)) != 0) {
	  giterr_set(GITERR_INVALID, "Corrupted bitmap index file (wrong header)");
	  return -1;
	}

	p->bitmap_version = ntohs(header->version);
	if (p->bitmap_version != 1) {
	  giterr_set(GITERR_INVALID, "Unsupported version for bitmap index file (%d)", index->version);
	  return -1;
	}
	/* Parse known bitmap format options */
	{
		uint32_t flags = ntohs(header->options);

		if ((flags & BITMAP_OPT_FULL_DAG) == 0) {
		  giterr_set(GITERR_INVALID, "Unsupported options for bitmap index file "
			"(Git requires BITMAP_OPT_FULL_DAG)");
		  return -1;
		}

		if (flags & BITMAP_OPT_HASH_CACHE) {
			unsigned char *end = index->map + index->map_size - 20;
			index->hashes = ((uint32_t *)end) - index->pack->num_objects;
		}
	}

	index->entry_count = ntohl(header->entry_count);
	index->map_pos += sizeof(*header);
	return 0;
}

static struct stored_bitmap *store_bitmap(struct bitmap_index *index,
					  struct ewah_bitmap *root,
					  const git_oid *sha1,
					  struct stored_bitmap *xor_with,
					  int flags)
{
	struct stored_bitmap *stored;
	khiter_t hash_pos;
	int ret;

	stored = git__malloc(sizeof(struct stored_bitmap));
	stored->root = root;
	stored->xor = xor_with;
	stored->flags = flags;
	git_oid_cpy(&stored->sha1, sha1);

	hash_pos = kh_put_sha1(index->bitmaps, &stored->sha1, &ret);

	/* a 0 return code means the insertion succeeded with no changes,
	 * because the SHA1 already existed on the map. this is bad, there
	 * shouldn't be duplicated commits in the index */
	if (ret == 0) {
	  char oid_str[GIT_OID_HEXSZ + 1];
	  git_oid_tostr(oid_str, sizeof(oid_str), sha1);
	  giterr_set(GITERR_INVALID, "Duplicate entry in bitmap index: %s", oid_str);
	  return NULL;
	}

	kh_value(index->bitmaps, hash_pos) = stored;
	return stored;
}

static inline uint32_t read_be32(const unsigned char *buffer, size_t *pos)
{
	uint32_t result = get_be32(buffer + *pos);
	(*pos) += sizeof(result);
	return result;
}

static inline uint8_t read_u8(const unsigned char *buffer, size_t *pos)
{
	return buffer[(*pos)++];
}

#define MAX_XOR_OFFSET 160

static int load_bitmap_entries_v1(struct bitmap_index *index)
{
	uint32_t i;
	int error = 0;
	struct stored_bitmap *recent_bitmaps[MAX_XOR_OFFSET] = { NULL };

	for (i = 0; i < index->entry_count; ++i) {
		int xor_offset, flags;
		struct ewah_bitmap *bitmap = NULL;
		struct stored_bitmap *xor_bitmap = NULL;
		uint32_t commit_idx_pos;
		git_off_t offset;
		git_oid* id;

		commit_idx_pos = read_be32(index->map, &index->map_pos);
		xor_offset = read_u8(index->map, &index->map_pos);
		flags = read_u8(index->map, &index->map_pos);

		if ((error = git_packfile_get_entry(&id, &offset, index->pack, commit_idx_pos)) < 0) {
		  return error;
		}

		if ((error = read_bitmap_1(index, &bitmap)) < 0)
			return error;

		if (xor_offset > MAX_XOR_OFFSET || xor_offset > i) {
		  giterr_set(GITERR_INVALID, "Corrupted bitmap pack index");
		  return -1;
		}

		if (xor_offset > 0) {
			xor_bitmap = recent_bitmaps[(i - xor_offset) % MAX_XOR_OFFSET];

			if (xor_bitmap == NULL) {
			  giterr_set(GITERR_INVALID, "Invalid XOR offset in bitmap pack index");
			  return -1;
			}
		}

		recent_bitmaps[i % MAX_XOR_OFFSET] = store_bitmap(
			index, bitmap, id, xor_bitmap, flags);
	}

	return 0;
}

int pack_index_open(struct git_pack_file *p);

static int open_pack_bitmap(struct git_pack_file *p, const char* idx_name)
{
	uint32_t version, nr, i, *index;
	git_file fd;
	struct stat st;
	void *idx_map;
	size_t idx_size;
	int error;

	if (p->index_version == -1 && pack_index_open(p) < 0)
		return -1;

	/* TODO: properly open the file without access time using O_NOATIME */
	fd = git_futils_open_ro(idx_name);
	if (fd < 0)
	  return fd;

	if (p_fstat(fd, &st) < 0) {
	  p_close(fd);
	  giterr_set(GITERR_OS, "unable to stat pack bitmap '%s'", idx_name);
	  return -1;
	}

	if (!S_ISREG(st.st_mode) ||
	  !git__is_sizet(st.st_size) ||
	  (idx_size = (size_t)st.st_size) < 4 * 256 + 20 + 20) {
	  p_close(fd);
	  giterr_set(GITERR_ODB, "invalid pack bitmap '%s'", idx_name);
	  return -1;
	}

	error = git_futils_mmap_ro(&p->bitmap_map, fd, 0, idx_size);

	p_close(fd);

	if (error < 0)
	  return error;

	bitmap_git.pack = p;
	bitmap_git.map_size = st.st_size;
	bitmap_git.map = p->bitmap_map.data;
	bitmap_git.map_pos = 0;
	close(fd);

	if (load_bitmap_header(p, &bitmap_git) < 0) {
		git_futils_mmap_free(&p->bitmap_map);
		bitmap_git.map = NULL;
		bitmap_git.map_size = 0;
		return -1;
	}

	return 0;
}

int pack_bitmap_open(struct git_pack_file *p)
{
  int error = 0;
  size_t name_len;
  git_buf idx_name;

  if (p->bitmap_version > -1)
	return 0;

  name_len = strlen(p->pack_name);
  assert(name_len > strlen(".pack")); /* checked by git_pack_file alloc */

  if (git_buf_init(&idx_name, name_len) < 0)
	return -1;

  git_buf_put(&idx_name, p->pack_name, name_len - strlen(".pack"));
  git_buf_puts(&idx_name, ".bitmap");
  if (git_buf_oom(&idx_name)) {
	git_buf_free(&idx_name);
	return -1;
  }

  if ((error = git_mutex_lock(&p->lock)) < 0) {
	git_buf_free(&idx_name);
	return error;
  }

  if (p->bitmap_version == -1)
	error = open_pack_bitmap(p, idx_name.ptr);

  git_buf_free(&idx_name);

  git_mutex_unlock(&p->lock);

  return error;
}

static int load_pack_bitmap(void)
{
	assert(bitmap_git.map && !bitmap_git.loaded);

	bitmap_git.bitmaps = kh_init_sha1();
	bitmap_git.ext_index.positions = kh_init_sha1_pos();
	//load_pack_revindex(bitmap_git.pack);
	//bitmap_git.pack->index_map

	if (read_bitmap_1(&bitmap_git, &bitmap_git.commits) < 0 ||
		  read_bitmap_1(&bitmap_git, &bitmap_git.trees) < 0 ||
		  read_bitmap_1(&bitmap_git, &bitmap_git.blobs) < 0 ||
		  read_bitmap_1(&bitmap_git, &bitmap_git.tags) < 0)
		goto failed;

	if (load_bitmap_entries_v1(&bitmap_git) < 0)
		goto failed;

	bitmap_git.loaded = 1;
	return 0;

failed:
	munmap(bitmap_git.map, bitmap_git.map_size);
	bitmap_git.map = NULL;
	bitmap_git.map_size = 0;
	return -1;
}


struct include_data {
	struct bitmap *base;
	struct bitmap *seen;
};

static inline int bitmap_position_extended(git_oid *sha1)
{
	khash_sha1_pos *positions = bitmap_git.ext_index.positions;
	khiter_t pos = kh_get_sha1_pos(positions, sha1);

	if (pos < kh_end(positions)) {
		int bitmap_pos = kh_value(positions, pos);
		return bitmap_pos + bitmap_git.pack->num_objects;
	}

	return -1;
}

static inline int bitmap_position_packfile(git_oid *sha1)
{
	struct git_pack_cache_entry *e;
	int error = git_pack_entry_find(&e, bitmap_git.pack, sha1, GIT_OID_HEXSZ);
	if (!error)
		return -1;

	return find_revindex_position(bitmap_git.pack, error);
}

static int bitmap_position(git_oid *sha1)
{
	int pos = bitmap_position_packfile(sha1);
	return (pos >= 0) ? pos : bitmap_position_extended(sha1);
}

static inline uint32_t pack_name_hash(const char *name)
{
  uint32_t c, hash = 0;

  if (!name)
	return 0;

  /*
  * This effectively just creates a sortable number from the
  * last sixteen non-whitespace characters. Last characters
  * count "most", so things that end in ".c" sort together.
  */
  while ((c = *name++) != 0) {
	if (isspace(c))
	  continue;
	hash = (hash >> 2) + (c << 24);
  }
  return hash;
}

static int ext_index_add_object(struct object *object, const char *name)
{
	struct eindex *eindex = &bitmap_git.ext_index;

	khiter_t hash_pos;
	int hash_ret;
	int bitmap_pos;

	hash_pos = kh_put_sha1_pos(eindex->positions, &object->oid, &hash_ret);
	if (hash_ret > 0) {
		if (eindex->count >= eindex->alloc) {
			eindex->alloc = (eindex->alloc + 16) * 3 / 2;
			git__reallocarray(eindex->objects, eindex->alloc, sizeof(void*));
			git__reallocarray(eindex->hashes, eindex->alloc, sizeof(void*));
		}

		bitmap_pos = eindex->count;
		eindex->objects[eindex->count] = object;
		eindex->hashes[eindex->count] = pack_name_hash(name);
		kh_value(eindex->positions, hash_pos) = bitmap_pos;
		eindex->count++;
	} else {
		bitmap_pos = kh_value(eindex->positions, hash_pos);
	}

	return bitmap_pos + bitmap_git.pack->num_objects;
}

static void show_object(struct object *object, const char *name, void *data)
{
	struct bitmap *base = data;
	int bitmap_pos;

	bitmap_pos = bitmap_position(&object->oid);

	if (bitmap_pos < 0)
		bitmap_pos = ext_index_add_object(object, name);

	bitmap_set(base, bitmap_pos);
}

static void show_commit(struct commit *commit, void *data)
{
}

static int add_to_include_set(struct include_data *data,
			      const unsigned char *sha1,
			      int bitmap_pos)
{
	khiter_t hash_pos;

	if (data->seen && bitmap_get(data->seen, bitmap_pos))
		return 0;

	if (bitmap_get(data->base, bitmap_pos))
		return 0;

	hash_pos = kh_get_sha1(bitmap_git.bitmaps, sha1);
	if (hash_pos < kh_end(bitmap_git.bitmaps)) {
		struct stored_bitmap *st = kh_value(bitmap_git.bitmaps, hash_pos);
		bitmap_or_ewah(data->base, lookup_stored_bitmap(st));
		return 0;
	}

	bitmap_set(data->base, bitmap_pos);
	return 1;
}

static int should_include(struct git_commit *commit, void *_data)
{
	struct include_data *data = _data;
	int bitmap_pos;
	
	bitmap_pos = bitmap_position(&commit->object.cached.oid);
	if (bitmap_pos < 0)
		bitmap_pos = ext_index_add_object((struct object *)commit, NULL);

	if (!add_to_include_set(data, &commit->object.cached.oid, bitmap_pos)) {
	  for(int i = 0; i != git_array_size(commit->parent_ids) ;i++){
		struct git_oid *parent = git_array_get(commit->parent_ids, i);

		//while (parent) {
		 // parent->item->object.flags |= SEEN;
		//  parent = parent->next;
		//}
	  }
	  return 0;
	}

	return 1;
}

static struct bitmap *find_objects(struct rev_info *revs,
				   struct object_list *roots,
				   struct bitmap *seen)
{
	struct bitmap *base = NULL;
	int needs_walk = 0;

	struct object_list *not_mapped = NULL;


	/*
	 * Go through all the roots for the walk. The ones that have bitmaps
	 * on the bitmap index will be `or`ed together to form an initial
	 * global reachability analysis.
	 *
	 * The ones without bitmaps in the index will be stored in the
	 * `not_mapped_list` for further processing.
	 */
	while (roots) {
		struct git_pobject *object = roots->item;
		roots = roots->next;

		if (object->type == GIT_OBJ_COMMIT) {
			khiter_t pos = kh_get_sha1(bitmap_git.bitmaps, &object->id);

			if (pos < kh_end(bitmap_git.bitmaps)) {
				struct stored_bitmap *st = kh_value(bitmap_git.bitmaps, pos);
				struct ewah_bitmap *or_with = lookup_stored_bitmap(st);

				if (base == NULL)
					base = ewah_to_bitmap(or_with);
				else
					bitmap_or_ewah(base, or_with);

				object->tagged = 1;
				continue;
			}
		}
		git_vector_insert()
		object_list_insert(object, &not_mapped);
	}

	/*
	 * Best case scenario: We found bitmaps for all the roots,
	 * so the resulting `or` bitmap has the full reachability analysis
	 */
	if (not_mapped == NULL)
		return base;

	roots = not_mapped;

	/*
	 * Let's iterate through all the roots that don't have bitmaps to
	 * check if we can determine them to be reachable from the existing
	 * global bitmap.
	 *
	 * If we cannot find them in the existing global bitmap, we'll need
	 * to push them to an actual walk and run it until we can confirm
	 * they are reachable
	 */
	while (roots) {
		struct object *object = roots->item;
		int pos;

		roots = roots->next;
		pos = bitmap_position(object->oid.hash);

		if (pos < 0 || base == NULL || !bitmap_get(base, pos)) {
			object->flags &= ~UNINTERESTING;
			add_pending_object(revs, object, "");
			needs_walk = 1;
		} else {
			object->flags |= SEEN;
		}
	}

	if (needs_walk) {
		struct include_data incdata;

		if (base == NULL)
			base = bitmap_new();

		incdata.base = base;
		incdata.seen = seen;

		revs->include_check = should_include;
		revs->include_check_data = &incdata;

		if (prepare_revision_walk(revs))
			die("revision walk setup failed");

		traverse_commit_list(revs, show_commit, show_object, base);
	}

	return base;
}

static void show_extended_objects(struct bitmap *objects,
				  show_reachable_fn show_reach)
{
	struct eindex *eindex = &bitmap_git.ext_index;
	uint32_t i;

	for (i = 0; i < eindex->count; ++i) {
		struct object *obj;

		if (!bitmap_get(objects, bitmap_git.pack->num_objects + i))
			continue;

		obj = eindex->objects[i];
		show_reach(&obj->oid, obj->type, 0, eindex->hashes[i], NULL, 0);
	}
}

static void show_objects_for_type(
	struct bitmap *objects,
	struct ewah_bitmap *type_filter,
	enum object_type object_type,
	show_reachable_fn show_reach)
{
	size_t pos = 0, i = 0;
	uint32_t offset;

	struct ewah_iterator it;
	eword_t filter;

	if (bitmap_git.reuse_objects == bitmap_git.pack->num_objects)
		return;

	ewah_iterator_init(&it, type_filter);

	while (i < objects->word_alloc && ewah_iterator_next(&filter, &it)) {
		eword_t word = objects->words[i] & filter;

		for (offset = 0; offset < BITS_IN_EWORD; ++offset) {
			git_oid oid;
			struct revindex_entry *entry;
			uint32_t hash = 0;

			if ((word >> offset) == 0)
				break;

			offset += ewah_bit_ctz64(word >> offset);

			if (pos + offset < bitmap_git.reuse_objects)
				continue;

			entry = &bitmap_git.pack->revindex[pos + offset];
			nth_packed_object_oid(&oid, bitmap_git.pack, entry->nr);

			if (bitmap_git.hashes)
				hash = get_be32(bitmap_git.hashes + entry->nr);

			show_reach(&oid, object_type, 0, hash, bitmap_git.pack, entry->offset);
		}

		pos += BITS_IN_EWORD;
		i++;
	}
}

static int in_bitmapped_pack(struct object_list *roots)
{
	while (roots) {
		struct object *object = roots->item;
		roots = roots->next;

		if (find_pack_entry_one(object->oid.hash, bitmap_git.pack) > 0)
			return 1;
	}

	return 0;
}

int prepare_bitmap_walk(struct rev_info *revs)
{
	unsigned int i;

	struct object_list *wants = NULL;
	struct object_list *haves = NULL;

	struct bitmap *wants_bitmap = NULL;
	struct bitmap *haves_bitmap = NULL;

	if (!bitmap_git.loaded) {
		/* try to open a bitmapped pack, but don't parse it yet
		 * because we may not need to use it */
		if (open_pack_bitmap() < 0)
			return -1;
	}

	for (i = 0; i < revs->pending.nr; ++i) {
		struct object *object = revs->pending.objects[i].item;

		if (object->type == GIT_OBJ_NONE)
			parse_object_or_die(&object->oid, NULL);

		while (object->type == GIT_OBJ_TAG) {
			struct tag *tag = (struct tag *) object;

			if (object->flags & UNINTERESTING)
				object_list_insert(object, &haves);
			else
				object_list_insert(object, &wants);

			if (!tag->tagged)
				die("bad tag");
			object = parse_object_or_die(&tag->tagged->oid, NULL);
		}

		if (object->flags & UNINTERESTING)
			object_list_insert(object, &haves);
		else
			object_list_insert(object, &wants);
	}

	/*
	 * if we have a HAVES list, but none of those haves is contained
	 * in the packfile that has a bitmap, we don't have anything to
	 * optimize here
	 */
	if (haves && !in_bitmapped_pack(haves))
		return -1;

	/* if we don't want anything, we're done here */
	if (!wants)
		return -1;

	/*
	 * now we're going to use bitmaps, so load the actual bitmap entries
	 * from disk. this is the point of no return; after this the rev_list
	 * becomes invalidated and we must perform the revwalk through bitmaps
	 */
	if (!bitmap_git.loaded && load_pack_bitmap() < 0)
		return -1;

	object_array_clear(&revs->pending);

	if (haves) {
		revs->ignore_missing_links = 1;
		haves_bitmap = find_objects(revs, haves, NULL);
		reset_revision_walk();
		revs->ignore_missing_links = 0;

		if (haves_bitmap == NULL)
			die("BUG: failed to perform bitmap walk");
	}

	wants_bitmap = find_objects(revs, wants, haves_bitmap);

	if (!wants_bitmap)
		die("BUG: failed to perform bitmap walk");

	if (haves_bitmap)
		bitmap_and_not(wants_bitmap, haves_bitmap);

	bitmap_git.result = wants_bitmap;

	bitmap_free(haves_bitmap);
	return 0;
}

int reuse_partial_packfile_from_bitmap(struct packed_git **packfile,
				       uint32_t *entries,
				       off_t *up_to)
{
	/*
	 * Reuse the packfile content if we need more than
	 * 90% of its objects
	 */
	static const double REUSE_PERCENT = 0.9;

	struct bitmap *result = bitmap_git.result;
	uint32_t reuse_threshold;
	uint32_t i, reuse_objects = 0;

	assert(result);

	for (i = 0; i < result->word_alloc; ++i) {
		if (result->words[i] != (eword_t)~0) {
			reuse_objects += ewah_bit_ctz64(~result->words[i]);
			break;
		}

		reuse_objects += BITS_IN_EWORD;
	}

#ifdef GIT_BITMAP_DEBUG
	{
		const unsigned char *sha1;
		struct revindex_entry *entry;

		entry = &bitmap_git.reverse_index->revindex[reuse_objects];
		sha1 = nth_packed_object_sha1(bitmap_git.pack, entry->nr);

		fprintf(stderr, "Failed to reuse at %d (%016llx)\n",
			reuse_objects, result->words[i]);
		fprintf(stderr, " %s\n", sha1_to_hex(sha1));
	}
#endif

	if (!reuse_objects)
		return -1;

	if (reuse_objects >= bitmap_git.pack->num_objects) {
		bitmap_git.reuse_objects = *entries = bitmap_git.pack->num_objects;
		*up_to = -1; /* reuse the full pack */
		*packfile = bitmap_git.pack;
		return 0;
	}

	reuse_threshold = bitmap_popcount(bitmap_git.result) * REUSE_PERCENT;

	if (reuse_objects < reuse_threshold)
		return -1;

	bitmap_git.reuse_objects = *entries = reuse_objects;
	*up_to = bitmap_git.pack->revindex[reuse_objects].offset;
	*packfile = bitmap_git.pack;

	return 0;
}

void traverse_bitmap_commit_list(show_reachable_fn show_reachable)
{
	assert(bitmap_git.result);

	show_objects_for_type(bitmap_git.result, bitmap_git.commits,
		GIT_OBJ_COMMIT, show_reachable);
	show_objects_for_type(bitmap_git.result, bitmap_git.trees,
		GIT_OBJ_TREE, show_reachable);
	show_objects_for_type(bitmap_git.result, bitmap_git.blobs,
		GIT_OBJ_BLOB, show_reachable);
	show_objects_for_type(bitmap_git.result, bitmap_git.tags,
		GIT_OBJ_TAG, show_reachable);

	show_extended_objects(bitmap_git.result, show_reachable);

	bitmap_free(bitmap_git.result);
	bitmap_git.result = NULL;
}

static uint32_t count_object_type(struct bitmap *objects,
				  enum object_type type)
{
	struct eindex *eindex = &bitmap_git.ext_index;

	uint32_t i = 0, count = 0;
	struct ewah_iterator it;
	eword_t filter;

	switch (type) {
	case GIT_OBJ_COMMIT:
		ewah_iterator_init(&it, bitmap_git.commits);
		break;

	case GIT_OBJ_TREE:
		ewah_iterator_init(&it, bitmap_git.trees);
		break;

	case GIT_OBJ_BLOB:
		ewah_iterator_init(&it, bitmap_git.blobs);
		break;

	case GIT_OBJ_TAG:
		ewah_iterator_init(&it, bitmap_git.tags);
		break;

	default:
		return 0;
	}

	while (i < objects->word_alloc && ewah_iterator_next(&filter, &it)) {
		eword_t word = objects->words[i++] & filter;
		count += ewah_bit_popcount64(word);
	}

	for (i = 0; i < eindex->count; ++i) {
		if (eindex->objects[i]->type == type &&
			bitmap_get(objects, bitmap_git.pack->num_objects + i))
			count++;
	}

	return count;
}

void count_bitmap_commit_list(uint32_t *commits, uint32_t *trees,
			      uint32_t *blobs, uint32_t *tags)
{
	assert(bitmap_git.result);

	if (commits)
		*commits = count_object_type(bitmap_git.result, GIT_OBJ_COMMIT);

	if (trees)
		*trees = count_object_type(bitmap_git.result, GIT_OBJ_TREE);

	if (blobs)
		*blobs = count_object_type(bitmap_git.result, GIT_OBJ_BLOB);

	if (tags)
		*tags = count_object_type(bitmap_git.result, GIT_OBJ_TAG);
}

struct bitmap_test_data {
	struct bitmap *base;
	struct progress *prg;
	size_t seen;
};


static int rebuild_bitmap(uint32_t *reposition,
			  struct ewah_bitmap *source,
			  struct bitmap *dest)
{
	uint32_t pos = 0;
	struct ewah_iterator it;
	eword_t word;

	ewah_iterator_init(&it, source);

	while (ewah_iterator_next(&word, &it)) {
		uint32_t offset, bit_pos;

		for (offset = 0; offset < BITS_IN_EWORD; ++offset) {
			if ((word >> offset) == 0)
				break;

			offset += ewah_bit_ctz64(word >> offset);

			bit_pos = reposition[pos + offset];
			if (bit_pos > 0)
				bitmap_set(dest, bit_pos - 1);
			else /* can't reuse, we don't have the object */
				return -1;
		}

		pos += BITS_IN_EWORD;
	}
	return 0;
}

int rebuild_existing_bitmaps(struct packing_data *mapping,
			     khash_sha1 *reused_bitmaps,
			     int show_progress)
{
	uint32_t i, num_objects;
	uint32_t *reposition;
	struct bitmap *rebuild;
	struct stored_bitmap *stored;
	struct progress *progress = NULL;

	khiter_t hash_pos;
	int hash_ret;

	if (prepare_bitmap_git() < 0)
		return -1;

	num_objects = bitmap_git.pack->num_objects;
	reposition = git__calloc(num_objects, sizeof(uint32_t));

	for (i = 0; i < num_objects; ++i) {
		const unsigned char *sha1;
		struct revindex_entry *entry;
		struct object_entry *oe;

		entry = &bitmap_git.pack->revindex[i];
		sha1 = nth_packed_object_sha1(bitmap_git.pack, entry->nr);
		oe = packlist_find(mapping, sha1, NULL);

		if (oe)
			reposition[i] = oe->in_pack_pos + 1;
	}

	rebuild = bitmap_new();
	i = 0;

	if (show_progress)
		progress = start_progress("Reusing bitmaps", 0);

	kh_foreach_value(bitmap_git.bitmaps, stored, {
		if (stored->flags & BITMAP_FLAG_REUSE) {
			if (!rebuild_bitmap(reposition,
					    lookup_stored_bitmap(stored),
					    rebuild)) {
				hash_pos = kh_put_sha1(reused_bitmaps,
						       &stored->sha1,
						       &hash_ret);
				kh_value(reused_bitmaps, hash_pos) =
					bitmap_to_ewah(rebuild);
			}
			bitmap_reset(rebuild);
			display_progress(progress, ++i);
		}
	});

	stop_progress(&progress);

	free(reposition);
	bitmap_free(rebuild);
	return 0;
}
