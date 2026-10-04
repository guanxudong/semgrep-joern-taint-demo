# Ground-truth marker comments must never reach an LLM (red line §9.2).
#
# The targets themselves are marker-free since D15 (2026-09-26), which means
# the repo no longer carries a natural fixture for the scrubber. These files
# ARE that fixture: deliberate label shapes, one per known leak form. They
# live under tests/, never under targets/ (which stays marker-free).
#
# Covered forms (one file each):
#   hash_line_start       `# VULN: id` at column 0
#   hash_indented         indented `# SAFE: id` inside a function body
#   numbered_line         read_function output: `  12: # VULN: id`
#   rg_prefixed           search_code output: `path:41:  // VULN: id`
#   html_comment          `<!-- SAFE: id -->`
#   block_star            block-comment continuation ` * VULN: id`
#   block_inline          `/* VULN: id */ trailing code on the same line`
#   cstyle_trailing       `// SAFE: id` at end of a statement line
#   gt_id_only            bare ground-truth id, no VULN:/SAFE: word
#   no_space              `#VULN:id` with no space after the comment opener
#   clean                 the control: a handler with no label at all
