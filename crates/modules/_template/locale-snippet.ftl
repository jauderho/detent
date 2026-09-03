## TEMPLATE module — display name, security notes, schema tooltips
TEMPLATE-name = TEMPLATE
TEMPLATE-note-precedence = this file overrides the compiled-in defaults; a wrong value silently changes behavior.
TEMPLATE-tip-settings = the `key value` settings in this file, in file order.
TEMPLATE-tip-key = the directive name, one word.
TEMPLATE-tip-value = the value of this directive, up to the end of the line.
TEMPLATE-rec-value = prefer an explicit value over relying on the compiled-in default.

## TEMPLATE module — validation diagnostics
TEMPLATE-invalid-key = `{$key}` is not a valid directive name.
TEMPLATE-duplicate-key = `{$key}` is set more than once; the last value wins.
TEMPLATE-too-many-settings = this file has {$count} settings; split it into drop-in files.
