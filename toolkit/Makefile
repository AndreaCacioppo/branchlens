# Exit code of ./preflight.sh: 0 PASSED, 1 FAILED, 2 INCONCLUSIVE, 4 usage.
# make reports any non-zero code as 2; call ./preflight.sh to tell them apart.

.PHONY: check run baseline help install-skills skills-status test

help:
	@echo "make check REPO=/path/to/repo   -> before every merge request"
	@echo "make check REPO=/path/to/repo BASE=origin/your-branch"
	@echo "make check REPO=/path/to/repo WORKTREE=1   -> judge uncommitted work"
	@echo "make run REPO=/path/to/repo     -> gate, then the LLM review (claude -p)"
	@echo "make test                       -> the toolkit's own test suite"
	@echo "make skills-status              -> do the installed skills and workflow match this checkout?"
	@echo "make install-skills             -> copy them into ~/.claude/"
	@echo ""
	@echo "Reports: \$$PREFLIGHT_REPORTS_DIR if set and not empty, else \$$HOME/preflight-reports/<main repository folder name>/"

check:
	@test -n "$(REPO)" || { echo "ERROR: say which repository: make check REPO=/path/to/repo"; exit 4; }
	@./preflight.sh check "$(REPO)" $(BASE) $(if $(WORKTREE),--worktree)

run:
	@test -n "$(REPO)" || { echo "ERROR: say which repository: make run REPO=/path/to/repo"; exit 4; }
	@./preflight.sh run "$(REPO)" $(BASE)

baseline:
	@./preflight.sh baseline

test:
	@python3 -m pytest tests/ -q

# The workflow goes to ~/.claude/workflows so the skill can start it by name.
SKILLS_DIR ?= $(HOME)/.claude/skills
WORKFLOWS_DIR ?= $(HOME)/.claude/workflows

skills-status:
	@for dir in setup/skill-*/; do \
	    name=$$(basename "$$dir" | sed 's/^skill-//'); \
	    installed="$(SKILLS_DIR)/$$name"; \
	    if [ ! -f "$$installed/SKILL.md" ]; then \
	        echo "NOT INSTALLED  $$name"; \
	    elif diff -rq "$$dir" "$$installed" >/dev/null; then \
	        echo "in sync        $$name"; \
	    else \
	        echo "OUT OF DATE    $$name  ($$installed)"; \
	    fi; \
	done
	@installed="$(WORKFLOWS_DIR)/review-diff.js"; \
	if [ ! -f "$$installed" ]; then \
	    echo "NOT INSTALLED  workflow review-diff"; \
	elif cmp -s checks/review/review-diff.js "$$installed"; then \
	    echo "in sync        workflow review-diff"; \
	else \
	    echo "OUT OF DATE    workflow review-diff  ($$installed)"; \
	fi
	@echo "(run 'make install-skills', then /reload-skills, to refresh anything out of date)"

install-skills:
	@for dir in setup/skill-*/; do \
	    name=$$(basename "$$dir" | sed 's/^skill-//'); \
	    mkdir -p "$(SKILLS_DIR)/$$name"; \
	    cp -R "$$dir". "$(SKILLS_DIR)/$$name/"; \
	    echo "installed      $$name -> $(SKILLS_DIR)/$$name"; \
	done
	@mkdir -p "$(WORKFLOWS_DIR)"
	@cp checks/review/review-diff.js "$(WORKFLOWS_DIR)/review-diff.js"
	@echo "installed      workflow review-diff -> $(WORKFLOWS_DIR)/review-diff.js"
	@echo "now run /reload-skills in Claude Code (or start a new session)"
