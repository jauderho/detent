#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * The ABI version this build exposes. Bumping requires a SONAME bump.
 */
#define DETENT_ABI_VERSION 0

/**
 * C-visible success.
 */
#define DETENT_OK 0

/**
 * A required pointer argument was NULL.
 */
#define DETENT_ERR_NULL_ARGUMENT 1

/**
 * A byte slice was not valid UTF-8.
 */
#define DETENT_ERR_INVALID_UTF8 2

/**
 * The requested `module_id` is not in the registry.
 */
#define DETENT_ERR_UNKNOWN_MODULE 3

/**
 * `ConfigModule::parse` rejected the input.
 */
#define DETENT_ERR_PARSE 4

/**
 * A model JSON could not be deserialized, or a document could not be projected.
 */
#define DETENT_ERR_MODEL 5

/**
 * `ConfigModule::apply` rejected the edit.
 */
#define DETENT_ERR_EDIT 6

/**
 * A JSON input was syntactically invalid.
 */
#define DETENT_ERR_INVALID_JSON 7

/**
 * Allocation failed or an internal invariant was violated.
 */
#define DETENT_ERR_INTERNAL 8

/**
 * Returns the ABI version this build was compiled with.
 *
 * Bumped in lockstep with `DETENT_ABI_VERSION` in `include/detent.h`. Any
 * mismatch is a SONAME mismatch and the library should not be loaded.
 */
uint32_t detent_abi_version(void);

/**
 * Returns the message of the last error raised on this thread, or NULL when
 * the most recent call on this thread succeeded.
 *
 * The pointer is a borrow of the thread-local error slot: **any** later FFI
 * call on this thread invalidates it — including successful calls, which
 * clear the slot on entry — and may free the underlying buffer. Copy the
 * string immediately if you need to retain it.
 */
const char *detent_last_error_message(void);

/**
 * Lists the module ids this build was compiled with, as a JSON array of
 * strings (e.g. `["hosts","resolver"]`). The returned buffer is owned by
 * libdetent — release it with `detent_free`.
 */
char *detent_module_list(void);

/**
 * Parses `src` with the module identified by `module_id` and returns a
 * document handle. The handle must be released with `detent_free`. Returns
 * NULL on error; the code is in `detent_last_error_message()`.
 * # Safety
 *
 * `module_id` must point to a readable NUL-terminated C string;
 * `src` must be readable for `src_len` bytes and `src_len <= isize::MAX`.
 */
char *detent_parse(const char *module_id, const char *src, uintptr_t src_len);

/**
 * Renders a document back to text such that `render(parse(src)) == src`.
 *
 * Returns a malloced NUL-terminated buffer, or NULL on error. Release the
 * success return with `detent_free`.
 * # Safety
 *
 * `doc` must be NULL or a live handle from `detent_parse`. Anything else
 * is refused, but only live handles keep the no-UB guarantee auditable.
 */
char *detent_render(char *doc);

/**
 * Projects a document onto its typed model, returning the model as JSON.
 * Release the buffer with `detent_free`.
 *
 * # Safety
 *
 * `doc` must be NULL or a live handle from `detent_parse`.
 */
char *detent_to_model_json(char *doc);

/**
 * Applies `model_json` to `src` via the module and returns the rendered
 * text. Stateless: release every successful return with `detent_free`.
 *
 * # Safety
 *
 * `module_id` must point to a readable NUL-terminated C string;
 * `src` must be readable for `src_len` bytes with `src_len <= isize::MAX`;
 * `model_json` must be readable for `model_len` bytes with
 * `model_len <= isize::MAX`.
 */
char *detent_apply_json(const char *module_id,
                        const char *src,
                        uintptr_t src_len,
                        const char *model_json,
                        uintptr_t model_len);

/**
 * Validates a model JSON against the module's schema plus its
 * `ConfigModule::validate` checks. Returns the diagnostics as a JSON array
 * (matching `detent_core::diag::Diagnostics`'s serialization). Release with
 * `detent_free`.
 *
 * # Safety
 *
 * `module_id` must point to a readable NUL-terminated C string;
 * `model_json` must be readable for `model_len` bytes with
 * `model_len <= isize::MAX`; `hostname` must be readable for
 * `hostname_len` bytes with `hostname_len <= isize::MAX`.
 */
char *detent_validate_json(const char *module_id,
                           const char *model_json,
                           uintptr_t model_len,
                           uint8_t os_id,
                           uint8_t init_id,
                           const char *hostname,
                           uintptr_t hostname_len,
                           uint64_t ram_mib);

/**
 * Returns the module's host-appropriate defaults as a JSON value matching
 * its model schema. `profile_json` is a `HostProfile`-shaped JSON object;
 * fields fall back to `Default::default()` when omitted.
 *
 * # Safety
 *
 * `module_id` must point to a readable NUL-terminated C string;
 * `profile_json` must be readable for `profile_len` bytes with
 * `profile_len <= isize::MAX`.
 */
char *detent_defaults_json(const char *module_id, const char *profile_json, uintptr_t profile_len);

/**
 * Returns the module's model schema as a JSON Schema document, including
 * any `x-detent` UI hints the module attaches. Release with `detent_free`.
 *
 * # Safety
 *
 * `module_id` must point to a readable NUL-terminated C string.
 */
char *detent_schema_json(const char *module_id);

/**
 * Frees any buffer or handle returned by this library. A `NULL` argument is
 * a no-op (matching `free(3)`).
 *
 * Passing a foreign pointer is safe (untracked hand-outs are refused before
 * any header read, and the pointer is left alone) but the buffer it points
 * at will leak. Passing an already-freed pointer is likewise refused while
 * its address is not reused by a later hand-out, so double-free detection
 * is best-effort (the first free's memory may already be reused).
 *
 * # Safety
 *
 * `ptr` must be either NULL or a pointer previously returned by a function
 * in this library (one of `detent_module_list`, `detent_parse`,
 * `detent_render`, `detent_to_model_json`, `detent_apply_json`,
 * `detent_validate_json`, `detent_defaults_json`, `detent_schema_json`).
 * Any other pointer is safely ignored but leaks relative to us.
 */
void detent_free(char *ptr);
