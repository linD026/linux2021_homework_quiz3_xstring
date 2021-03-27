#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "xstring.h"

#define large_string "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaax"
#define midium_string "aaaaaaaaaaaaaaaaa"
#define small_string "aaaaaaaa"

int main() {
    xs string;
    xs_new(&string, large_string);

    // detail    
    printf("string:\nsize %ld\n", xs_size(&string)); 
    printf("strlen %ld %s\n" , strlen(xs_data(&string)), xs_data(&string));
    printf("capacity %ld\n", (size_t)(1 << string.capacity));
    printf("\nlarge_string:\nstrlen %ld %s\n\n", strlen(large_string), large_string);

    // first store check
    assert(string.sharing == true);
    assert(!strcmp(xs_data(&string), large_string));
    printf("first store(hash table) check\n");

    // reclaim check
    assert(string.reclaim == 1);
    assert(strlen(xs_data(&string)) != (size_t)(1 << string.capacity) + 4);
    printf("reclaim(fixed size) check\n");

    // hash check
    xs check_grab;
    xs_new(&check_grab, large_string);
    assert(xs_data(&check_grab) == xs_data(&string));
    printf("grab string check\n");

    // action check
    xs prefix = *xs_tmp("xxxxxx y");
    xs suffix = *xs_tmp("y xxxxxx");
    char *string_address = xs_data(&string);
    xs_cow_write_concat(&string, &prefix, &suffix);
    assert(string_address != xs_data(&string));
    printf("concat \"xxxxxx y\", \"y xxxxxx\":\n%s\n", xs_data(&string));

    string_address = xs_data(&string);
    xs_cow_write_trim(&string, "x");
    assert(string_address != xs_data(&string));
    printf("trim \"x\":\n%s\naction check\n", xs_data(&string));

    xs small;
    xs_new(&small, small_string);
    assert(!xs_is_ptr(&small));
    printf("second store(stack) check\n");
}