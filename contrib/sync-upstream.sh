#!/usr/bin/env bash

set -eou pipefail

help() {
    echo "Sync merge commits from bitcoin-core/secp256k1 into secp256k1-zkp."
    echo
    echo "Usage:"
    echo "  $0 [-b <branch>] <pr_branch>"
    echo "      Find every merge commit present in upstream/master and missing in <branch> (default: master)."
    echo
    echo "This tool prepares the title and body for a sync PR"
    echo "and generates a helper script contrib/gh-pr-create.sh." 
    echo
    echo "Setup:"
    echo "  Requires a remote named 'upstream' pointing to bitcoin-core/secp256k1."
    echo
    echo "Listing upstream merge commits:"
    echo "  To list merge commits in upstream/master that are missing from <branch> (oldest first):"
    echo "    git log --oneline --topo-order --reverse --merges \$(git merge-base upstream/master <branch>)..upstream/master"
    exit 1
}

REMOTE=upstream
REMOTE_BRANCH="$REMOTE/master"
LOCAL_BRANCH="master"

if ! git remote get-url "$REMOTE" &> /dev/null; then
echo "Error: Remote '$REMOTE' not found."
echo "Add it with: git remote add upstream git@github.com:bitcoin-core/secp256k1.git"
echo "Then run: git fetch upstream"
exit 1
fi

range() {
    RANGESTART_COMMIT=$(git merge-base "$REMOTE_BRANCH" "$LOCAL_BRANCH")
    RANGEEND_COMMIT=$(git rev-parse "$REMOTE_BRANCH")
    COMMITS=$(git --no-pager log --pretty=format:%H --topo-order --reverse --merges "$RANGESTART_COMMIT".."$RANGEEND_COMMIT")
}

# Process -b <branch> and -h arguments
while getopts "b:h" opt; do
  case $opt in
    b)
      LOCAL_BRANCH=$OPTARG
      ;;
    h)
      help
      ;;
    *)
      echo
      help
      ;;
  esac
done

# Shift off the processed options
shift $((OPTIND -1))
if [ "$#" -lt 1 ]; then
    echo "Error: <pr_branch> argument is required." >&2
    echo
    help
    exit 1
fi

# Extract the PR branch argument
PR_BRANCH=$1          

range

TITLE="Upstream PRs"
BODY="${GITHUB_ACTIONS+This PR has been created by a GitHub Actions workflow without human involvement.}"$'\n'
for COMMIT in $COMMITS
do
    PRNUM=$(git log -1 "$COMMIT" --pretty=format:%s | sed s/'Merge \(bitcoin-core\/secp256k1\)\?#\([0-9]*\).*'/'\2'/)
    TITLE="$TITLE $PRNUM,"
    BODY=$(printf "%s\n%s" "$BODY" "$(git log -1 "$COMMIT" --pretty=format:%s | sed s/'Merge \(bitcoin-core\/secp256k1\)\?#\([0-9]*\)'/'[bitcoin-core\/secp256k1#\2]'/)")
    LAST_COMMIT="$COMMIT"
done
# Remove trailing ","
TITLE=${TITLE%?}
BODY+=$(cat <<EOF


Tips:
 * Use \`git show --remerge-diff <pr-branch>\` to show the conflict resolution in the merge commit.
 * Use \`git read-tree --reset -u <pr-branch>\` to replay these resolutions during the conflict resolution stage when recreating the PR branch locally.
   Be aware that this may discard your index as well as the uncommitted changes and untracked files in your worktree.
EOF
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

BASEDIR=$(dirname "$0")
FNAME="$BASEDIR/gh-pr-create.sh"
cat <<EOT > "$FNAME"
#!/bin/sh
gh pr create -t '$TITLE' -b '$BODY' --base '$LOCAL_BRANCH' --head '$PR_BRANCH'
EOT
chmod +x "$FNAME"
echo "Generated $FNAME for creating a pull request with the above title and body."