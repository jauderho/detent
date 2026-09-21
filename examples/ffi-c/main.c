/*
 * Minimal C consumer of libdetent (PLAN §2.6, §10).
 *
 * Builds against the generated header and one of the static or dynamic
 * variants of `libdetent`. Parses a `/etc/hosts`-shaped fixture into a model
 * via the FFI, edits it, renders it back, and asserts the rendered text
 * matches the fixture (hosts module's `render(parse(s)) == s` invariant).
 *
 *     cc -I include examples/ffi-c/main.c -L target/release \
 *        -ldetent -o examples/ffi-c/main
 *     ./examples/ffi-c/main [fixture-path]
 *
 * Defaults to `fixtures/hosts/glibc-2.42/debian-default.hosts` if no
 * fixture is given.
 *
 * The fixture path is small and well-known; nothing else is needed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "detent.h"

static char *read_fixture(const char *path, uintptr_t *out_len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror(path);
        exit(1);
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(fp);
        exit(1);
    }
    long sz = ftell(fp);
    if (sz < 0) {
        perror("ftell");
        fclose(fp);
        exit(1);
    }
    rewind(fp);
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        perror("malloc");
        fclose(fp);
        exit(1);
    }
    size_t got = fread(buf, 1, (size_t)sz, fp);
    if ((long)got != sz) {
        perror("fread");
        free(buf);
        fclose(fp);
        exit(1);
    }
    buf[sz] = '\0';
    fclose(fp);
    *out_len = (uintptr_t)sz;
    return buf;
}

static const char *getenv_or(const char *key, const char *fallback)
{
    const char *v = getenv(key);
    return (v && *v) ? v : fallback;
}

int main(int argc, char **argv)
{
    /* 0. ABI guard. */
    if (detent_abi_version() != DETENT_ABI_VERSION) {
        fprintf(stderr, "ABI mismatch: header %u, library %u\n",
                (unsigned)DETENT_ABI_VERSION,
                (unsigned)detent_abi_version());
        return 2;
    }

    /* 1. List modules. */
    char *mod_list = detent_module_list();
    if (!mod_list) {
        fprintf(stderr, "detent_module_list: %s\n", detent_last_error_message());
        return 1;
    }
    if (strstr(mod_list, "\"hosts\"") == NULL) {
        fprintf(stderr, "hosts module not built into this library (got: %s)\n",
                mod_list);
        detent_free(mod_list);
        return 1;
    }
    detent_free(mod_list);

    /* 2. Read the fixture. */
    const char *path = (argc > 1) ? argv[1]
        : getenv_or("DETENT_FIXTURE",
                    "fixtures/hosts/glibc-2.42/debian-default.hosts");
    uintptr_t src_len = 0;
    char *src = read_fixture(path, &src_len);

    /* 3. Parse. */
    char *doc = detent_parse("hosts", src, src_len);
    if (!doc) {
        fprintf(stderr, "detent_parse: %s\n", detent_last_error_message());
        free(src);
        return 1;
    }

    /* 4. Project to model JSON. */
    char *model = detent_to_model_json(doc);
    if (!model) {
        fprintf(stderr, "detent_to_model_json: %s\n", detent_last_error_message());
        detent_free(doc);
        free(src);
        return 1;
    }

    /* 5. Round-trip the model back through apply_json. Hosts module
     *    guarantee: render(parse(s)) == s. Compare bytes. */
    char *rendered = detent_apply_json("hosts", src, src_len, model, strlen(model));
    if (!rendered) {
        fprintf(stderr, "detent_apply_json: %s\n", detent_last_error_message());
        detent_free(model);
        detent_free(doc);
        free(src);
        return 1;
    }
    if ((strlen(rendered) != src_len) || memcmp(rendered, src, src_len) != 0) {
        fprintf(stderr, "rendered file does not match fixture\n");
        detent_free(rendered);
        detent_free(model);
        detent_free(doc);
        free(src);
        return 1;
    }
    detent_free(rendered);

    /* 6. Validate the model. Hosts fixture passes validation cleanly. */
    char *diags = detent_validate_json("hosts", model, strlen(model),
                                      0 /* Os::Linux */,
                                      1 /* InitSystem::Systemd */,
                                      "detent-test", strlen("detent-test"),
                                      1024);
    if (!diags) {
        fprintf(stderr, "detent_validate_json: %s\n", detent_last_error_message());
        detent_free(model);
        detent_free(doc);
        free(src);
        return 1;
    }
    /* The result is a JSON array; lengths at this fixture are small, but a
     * parse failure here would be visible as a non-array. */
    if (diags[0] != '[') {
        fprintf(stderr, "validate_json did not return a JSON array: %s\n", diags);
        detent_free(diags);
        detent_free(model);
        detent_free(doc);
        free(src);
        return 1;
    }
    detent_free(diags);

    /* 7. Pull the JSON Schema for the model. */
    char *schema = detent_schema_json("hosts");
    if (!schema || strstr(schema, "\"type\":\"object\"") == NULL) {
        fprintf(stderr, "schema_json returned an unexpected payload: %s\n",
                schema ? schema : detent_last_error_message());
        detent_free(schema);
        detent_free(model);
        detent_free(doc);
        free(src);
        return 1;
    }
    detent_free(schema);

    /* 8. Defaults for a Linux host. */
    const char *profile = "{\"os\":\"linux\",\"init\":\"systemd\","
                          "\"hostname\":\"detent-test\"}";
    char *defaults = detent_defaults_json("hosts", profile, strlen(profile));
    if (!defaults || strstr(defaults, "\"entries\"") == NULL) {
        fprintf(stderr, "defaults_json returned an unexpected payload: %s\n",
                defaults ? defaults : detent_last_error_message());
        detent_free(defaults);
        detent_free(model);
        detent_free(doc);
        free(src);
        return 1;
    }
    detent_free(defaults);

    /* 9. Free the doc handle and the model. */
    detent_free(model);
    detent_free(doc);
    free(src);

    printf("OK: parse + to_model_json + apply_json + validate_json + "
           "schema_json + defaults_json\n");
    return 0;
}
