/**
 * Copyright 2013, GitHub, Inc
 * Copyright 2009-2013, Daniel Lemire, Cliff Moon,
 *	David McIntosh, Robert Becho, Google Inc. and Veronika Zenz
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include "cache.h"
#include "ewok.h"

#define EWAH_MASK(x) ((eword_t)1 << (x % BITS_IN_EWORD))
#define EWAH_BLOCK(x) (x / BITS_IN_EWORD)

struct bitmap *bitmap_new(void)
{
	struct bitmap *bitmap = git__malloc(sizeof(struct bitmap));
	bitmap->words = git__calloc(32, sizeof(eword_t));
	bitmap->word_alloc = 32;
	return bitmap;
}

void bitmap_set(struct bitmap *self, size_t pos)
{
	size_t block = EWAH_BLOCK(pos);

	if (block >= self->word_alloc) {
		size_t old_size = self->word_alloc;
		self->word_alloc = block * 2;
		self->words = git__reallocarray(self->words, sizeof(eword_t), self->word_alloc);
		memset(self->words + old_size, 0x0,
			(self->word_alloc - old_size) * sizeof(eword_t));
	}

	self->words[block] |= EWAH_MASK(pos);
}

void bitmap_clear(struct bitmap *self, size_t pos)
{
	size_t block = EWAH_BLOCK(pos);

	if (block < self->word_alloc)
		self->words[block] &= ~EWAH_MASK(pos);
}

int bitmap_get(struct bitmap *self, size_t pos)
{
	size_t block = EWAH_BLOCK(pos);
	return block < self->word_alloc &&
		(self->words[block] & EWAH_MASK(pos)) != 0;
}

struct ewah_bitmap *bitmap_to_ewah(struct bitmap *bitmap)
{
	struct ewah_bitmap *ewah = ewah_new();
	size_t i, running_empty_words = 0;
	eword_t last_word = 0;

	for (i = 0; i < bitmap->word_alloc; ++i) {
		if (bitmap->words[i] == 0) {
			running_empty_words++;
			continue;
		}

		if (last_word != 0)
			ewah_add(ewah, last_word);

		if (running_empty_words > 0) {
			ewah_add_empty_words(ewah, 0, running_empty_words);
			running_empty_words = 0;
		}

		last_word = bitmap->words[i];
	}

	ewah_add(ewah, last_word);
	return ewah;
}

#define alloc_nr(x) (((x)+16)*3/2)

/*
* Realloc the buffer pointed at by variable 'x' so that it can hold
* at least 'nr' entries; the number of entries currently allocated
* is 'alloc', using the standard growing factor alloc_nr() macro.
*
* DO NOT USE any expression with side-effect for 'x', 'nr', or 'alloc'.
*/
#define ALLOC_GROW(x, nr, alloc) \
	do { \
		if ((nr) > alloc) { \
			if (alloc_nr(alloc) < (nr)) \
				alloc = (nr); \
			else \
				alloc = alloc_nr(alloc); \
			x = git__reallocarray(x, sizeof(*(x)), alloc); \
		} \
	} while (0)

struct bitmap *ewah_to_bitmap(struct ewah_bitmap *ewah)
{
	struct bitmap *bitmap = bitmap_new();
	struct ewah_iterator it;
	eword_t blowup;
	size_t i = 0;

	ewah_iterator_init(&it, ewah);

	while (ewah_iterator_next(&blowup, &it)) {
		ALLOC_GROW(bitmap->words, i + 1, bitmap->word_alloc);
		bitmap->words[i++] = blowup;
	}

	bitmap->word_alloc = i;
	return bitmap;
}

void bitmap_and_not(struct bitmap *self, struct bitmap *other)
{
	const size_t count = (self->word_alloc < other->word_alloc) ?
		self->word_alloc : other->word_alloc;

	size_t i;

	for (i = 0; i < count; ++i)
		self->words[i] &= ~other->words[i];
}

void bitmap_or_ewah(struct bitmap *self, struct ewah_bitmap *other)
{
	size_t original_size = self->word_alloc;
	size_t other_final = (other->bit_size / BITS_IN_EWORD) + 1;
	size_t i = 0;
	struct ewah_iterator it;
	eword_t word;

	if (self->word_alloc < other_final) {
		self->word_alloc = other_final;
		self->words = git__reallocarray(self->words, sizeof(eword_t), self->word_alloc);
		memset(self->words + original_size, 0x0,
			(self->word_alloc - original_size) * sizeof(eword_t));
	}

	ewah_iterator_init(&it, other);

	while (ewah_iterator_next(&word, &it))
		self->words[i++] |= word;
}

void bitmap_each_bit(struct bitmap *self, ewah_callback callback, void *data)
{
	size_t pos = 0, i;

	for (i = 0; i < self->word_alloc; ++i) {
		eword_t word = self->words[i];
		uint32_t offset;

		if (word == (eword_t)~0) {
			for (offset = 0; offset < BITS_IN_EWORD; ++offset)
				callback(pos++, data);
		} else {
			for (offset = 0; offset < BITS_IN_EWORD; ++offset) {
				if ((word >> offset) == 0)
					break;

				offset += ewah_bit_ctz64(word >> offset);
				callback(pos + offset, data);
			}
			pos += BITS_IN_EWORD;
		}
	}
}

size_t bitmap_popcount(struct bitmap *self)
{
	size_t i, count = 0;

	for (i = 0; i < self->word_alloc; ++i)
		count += ewah_bit_popcount64(self->words[i]);

	return count;
}

int bitmap_equals(struct bitmap *self, struct bitmap *other)
{
	struct bitmap *big, *smallb;
	size_t i;

	if (self->word_alloc < other->word_alloc) {
	  smallb = self;
		big = other;
	} else {
	  smallb = other;
		big = self;
	}

	for (i = 0; i < smallb->word_alloc; ++i) {
		if (smallb->words[i] != big->words[i])
			return 0;
	}

	for (; i < big->word_alloc; ++i) {
		if (big->words[i] != 0)
			return 0;
	}

	return 1;
}

void bitmap_reset(struct bitmap *bitmap)
{
	memset(bitmap->words, 0x0, bitmap->word_alloc * sizeof(eword_t));
}

void bitmap_free(struct bitmap *bitmap)
{
	if (bitmap == NULL)
		return;

	free(bitmap->words);
	free(bitmap);
}
