#include <WinSock2.h>
#include <windows.h>

#include "win32\thread.h"
#include "odb.h"
#include "pack.h"

#include <git2.h>
#include "git2\sys\odb_backend.h"
#include "git2\pack.h"

#include <stdio.h>


git_repository *repo;
git_odb *odb;

int counts[10] = {0};

void print_counts()
{
  printf("Commits: %d\n", counts[GIT_OBJ_COMMIT]);
  printf("Trees: %d\n", counts[GIT_OBJ_TREE]);
  printf("Blobs: %d\n", counts[GIT_OBJ_BLOB]);
  printf("Deltas(offset): %d\n", counts[GIT_OBJ_OFS_DELTA]);
  printf("Deltas(ref): %d\n", counts[GIT_OBJ_REF_DELTA]);
}

void reset_counts()
{
  memset(counts, 0, sizeof(counts));
}

int odb_foreach_cb(const git_oid *id, void *payload)
{
  git_odb_backend *backend = (git_odb_backend *)payload;
  size_t size = 0;
  git_otype otype = 0;
  git_oid oid;

  backend->read_header(&size, &otype, backend, id);

  counts[otype]++;
  return 0;
}

int packentry_foreach_cb(const git_oid *id, git_off_t ofs, void *payload)
{
  struct git_pack_file *pack = (struct git_pack_file *)payload;
  size_t size = 0;
  git_otype otype = 0;
  git_oid oid;

  git_packfile_get_header(&size, &otype, pack, ofs);
  counts[otype]++;

  if (otype == GIT_OBJ_OFS_DELTA || otype == GIT_OBJ_REF_DELTA) {
	git_packfile_resolve_header(&size, &otype, pack, ofs);
	//InterlockedAdd(&counts[otype], 1);
	counts[otype]++;
  }
  return 0;
}

struct git_pack_file *p;
size_t objcount;

typedef struct packthread_state{
  int start;
  int end;
  char pad[128];
  int counts[10];
} packthread_state;

void* packthread(packthread_state* state) {

  int start = state->start;
  int end = state->end;

  for (int j = start; j != end; j++) {
	const git_oid *id;
	git_off_t ofs;
	size_t size = 0;
	git_otype otype = 0;
	git_packfile_get_entry(&id, &ofs, p, j);
	git_packfile_get_header(&size, &otype, p, ofs);

	state->counts[otype]++;

	if (otype == GIT_OBJ_OFS_DELTA || otype == GIT_OBJ_REF_DELTA) {
	  git_packfile_resolve_header(&size, &otype, p, ofs);
	  state->counts[otype]++;
	} else {
	  git_rawobj obj;
	//  git_packfile_unpack(&obj, p, &ofs);
	}
  }

  return 0;
}

int walkpack_backend(git_odb_backend* obd_backend)
{
  int i;
  struct pack_backend* backend = (struct pack_backend*)obd_backend;
  size_t packbackends = git_packodb_packs_num(backend);

  for (i = 0; i != packbackends; i++) {
	git_packodb_getpack(&p, backend, i);
	objcount = git_packfile_obj_count(p);
	//reset_counts();
#if 1
	git_thread threads[4] = {0};
	packthread_state state[4] = {0};
	void* map = git_packfile_map_wholefile(p);

	int threadnum = 3;
	int rem = (objcount % threadnum);
	int split = (objcount - rem) / threadnum;

	int start = 0;

	for(int j = 0; j != threadnum; j++){
	  state[j].start = start;
	  state[j].end = start + split;
	  start += split;

	  if ((j-1) == threadnum) {
		state[j].end = objcount;
	  }

	  git_thread_create(&threads[j], packthread, state + j);
	}

	for (int j = 0; j != threadnum; j++) {
	  void* result;
	  git_thread_join(&threads[j], &result);

	  for(int n = 0; n != 10 ;n++){
		counts[n] += state[j].counts[n];
	  }
	  // CreateThread(NULL, 0, packthread, thread, 0, NULL);
	}
	git_packfile_unmap_wholefile(p, map);
#else
	git_packfile_foreach_entry2(p, packentry_foreach_cb, p);
#endif
	print_counts();
  }
}


int main(int argc, char **argv)
{

  git_libgit2_init();
  const char* path = "";

  if (argc > 2  /*|| argv[2] silence -Wunused-parameter */)
	fatal("Sorry, no for-each-ref options supported yet", NULL);

  check_lg2(git_repository_open(&repo, path),
	"Could not open repository", NULL);

  git_repository_odb(&odb, repo);

  size_t i, max_i = git_odb_num_backends(odb);
  git_odb_backend *obd_backend;

  git_odb_get_backend((git_odb_backend **)&obd_backend, odb, 0);

  walkpack_backend(obd_backend);

  //reset_counts();

  for (i = 1; i < max_i; ++i) {
	git_odb_get_backend((git_odb_backend **)&obd_backend, odb, i);

	obd_backend->foreach(obd_backend, odb_foreach_cb, obd_backend);
  }

  print_counts();

  git_libgit2_shutdown();
  return 0;
}
