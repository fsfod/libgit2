#include "common.h"
#include <zlib.h>
#include "git2/object.h"
#include "git2/oid.h"
#include "fileops.h"
#include "hash.h"
#include "odb.h"
#include "delta-apply.h"
#include "filebuf.h"

#include "repository.h"

#include "git2/odb_backend.h"
#include "git2/types.h"

extern int format_object_header(char *hdr, size_t n, size_t obj_len, git_otype obj_type);


static int save_object(git_odb_object* obj, const char* filePath, git_oid* outid){
	int error = 0, header_len;
	char header[64];
	git_filebuf fbuf = GIT_FILEBUF_INIT;

    //

	/* prepare the header for the file */
	header_len = format_object_header(header, sizeof(header), obj->cached.size, obj->cached.type);

	if(git_filebuf_open(&fbuf, filePath, GIT_FILEBUF_HASH_CONTENTS | ((Z_BEST_COMPRESSION+1) << GIT_FILEBUF_DEFLATE_SHIFT), 0) < 0){
		error = -1;
		goto cleanup;
	}

	git_filebuf_write(&fbuf, header, header_len);
    git_filebuf_write(&fbuf, obj->buffer, obj->cached.size);
	git_filebuf_hash(outid, &fbuf);

    if(error == 0)error = git_filebuf_commit(&fbuf, GIT_OBJECT_FILE_MODE);

cleanup:
	if (error < 0)git_filebuf_cleanup(&fbuf);

	return error;
}

GIT_EXTERN(int) git_export_to_loose_object(git_odb* odb, git_oid* id, const char* filePath){
  git_odb_object* object = NULL;
  git_oid checkId;
  int error = 0;

  error = git_odb_read(&object, odb, id);

  if(error != 0){
    return error;
  }

  error = save_object(object, filePath, &checkId);

  assert(git_oid_cmp(id, &checkId) == 0);

  git_odb_object_free(object);

  return error;
}