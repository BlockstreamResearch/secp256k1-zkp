#!/usr/bin/env bash

set -eou pipefail

help() {
cat <<EOT
$0: Prepare a pull request that syncs a branch with upstream

Usage:
  $0 <base-branch> <upstream-ref>

Arguments:
  <base-branch>: The branch to sync with upstream
  <upstream-ref>: The upstream ref to merge into <base-branch>

This script creates a local branch starting at <upstream-ref>. Moreover, it
generates a helper script for opening a pull request (PR) merging the created
local branch into <base-branch>.

The synced upstream PRs are listed in the title and the description of the PR.
(This relies on upstream merging PRs using merge commits with titles of the form
"Merge <repo>#<prnum>: ...".)

Usage examples:
  $0 origin/master upstream/master
  $0 origin/master abc1234

To find candidate merge commits from <upstream-ref> (oldest first), use:
  git log --oneline --topo-order --reverse --merges \$(git merge-base <upstream-ref> <base-branch>)..<upstream-ref>
EOT
}

# Parse arguments
if [ "$#" -ne 2 ]; then
    help
    exit 1
fi
BASE_BRANCH="$1"
UPSTREAM_REF="$2"

# Create a name for the sync branch
SYNC_BRANCH="sync-$(git rev-parse --short "$UPSTREAM_REF")"

# Create the sync branch locally.
# This will error out if the branch already exists, which is what we want.
git branch --no-track "$SYNC_BRANCH" "$UPSTREAM_REF"

# Create PR metadata
TITLE="Upstream PRs"
RANGESTART_COMMIT=$(git merge-base "$UPSTREAM_REF" "$BASE_BRANCH")
RANGEEND_COMMIT=$(git rev-parse "$UPSTREAM_REF")
COMMITS=$(git --no-pager log --pretty=format:%H --topo-order --reverse --merges "$RANGESTART_COMMIT".."$RANGEEND_COMMIT")
BODY="${GITHUB_ACTIONS+*Note: This PR has been created by a GitHub Actions workflow without human involvement.*

}"
BODY+="This PR syncs the following upstream PRs:"
for COMMIT in $COMMITS
do
    PRNUM=$(git log -1 "$COMMIT" --pretty=format:%s | sed s/'Merge \(.*\)\?#\([0-9]*\).*'/'\2'/)
    TITLE="$TITLE $PRNUM,"
    BODY=$(printf "%s\n * %s" "$BODY" "$(git log -1 "$COMMIT" --pretty=format:%s | sed s/'Merge '//)")
    done
# Remove trailing ","
TITLE=${TITLE%?}
BODY+=$(cat <<EOF


Tips:
 * Use \`git show --remerge-diff <pr-branch>\` to show the conflict resolution in the merge commit.
 * Use \`git read-tree --reset -u <pr-branch>\` to replay these resolutions during the conflict resolution stage when recreating the PR branch locally.
   Be aware that this may discard your index as well as the uncommitted changes and untracked files in your worktree.
EOF
# TODO
)

echo "-----------------------------------"
echo "$TITLE"
echo "-----------------------------------"
echo "$BODY"
echo "-----------------------------------"

# Escape single quote
# ' -> '\''
quote() {
    local quoted=${1//\'/\'\\\'\'}
    printf "%s" "$quoted"
}
TITLE=$(quote "$TITLE")
BODY=$(quote "$BODY")

FNAME="gh-pr-create.sh"
cat <<EOT > "$FNAME"
#!/bin/sh
TITLE='$TITLE'
BODY='$BODY'
SYNC_BRANCH='$SYNC_BRANCH'
BASE='$BASE_BRANCH'

gh pr create --base "\$BASE_BRANCH" --head "\$SYNC_BRANCH" --title "\$TITLE" --body "\$BODY" "\$@"
EOT
chmod +x "$FNAME"

echo "Successfully created local sync branch $SYNC_BRANCH starting at $UPSTREAM_REF."
echo
echo "You can now:"
echo "  1. Optionally resolve merge conflicts by merging $BASE_BRANCH into $SYNC_BRANCH."
echo "  2. Push $SYNC_BRANCH to some GitHub remote."
echo "  3. Run ./$FNAME to create a pull request. (Tip: Pass --dry-run first.)"
