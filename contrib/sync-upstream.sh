#!/usr/bin/env bash

set -eou pipefail

help() {
    echo "Sync merge commits from bitcoin-core/secp256k1 into secp256k1-zkp."
    echo
    echo "Usage:"
    echo "  $0 [-b <branch>] range [end]"
    echo "      Merges every merge commit present in upstream/master and missing in <branch>"
    echo "      (default: master). If the optional [end] commit is provided, only merges"
    echo "      up to and including [end]."
    echo
    echo "  $0 [-b <branch>] select <commit> ... <commit>"
    echo "      Merges every selected merge commit into <branch> (default: master)."
    echo
    echo "This tool creates a temporary branch and attempts to merge the upstream commits."
    echo "If there are merge conflicts, resolve them and run tests, then use the generated"
    echo "script contrib/gh-pr-create.sh to create the PR (requires the gh tool)."
    echo
    echo "Setup:"
    echo "  Requires a remote named 'upstream' pointing to bitcoin-core/secp256k1."
    echo "  The script will fetch it automatically, and offer to create it if missing."
    echo "  To add manually: git remote add upstream git@github.com:bitcoin-core/secp256k1.git"
    echo
    echo "Listing upstream merge commits:"
    echo "  To list merge commits in upstream/master that are missing from <branch> (oldest first):"
    echo "    git log --oneline --merges \$(git merge-base upstream/master <branch>)..upstream/master | tac"
    echo "  Use these for [end] in 'range' or as arguments to 'select'."
    exit 1
}

REMOTE=upstream
REMOTE_BRANCH="$REMOTE/master"
LOCAL_BRANCH="master"
# Makes sure you have a remote "upstream" that is up-to-date
setup() {
    ret=0
    git fetch "$REMOTE" &> /dev/null || ret="$?"
    if [ ${ret} == 0 ]; then
        return
    fi
    echo "Adding remote \"$REMOTE\" with URL git@github.com:bitcoin-core/secp256k1.git. Continue with y"
    read -r yn
    case $yn in
        [Yy]* ) ;;
        * ) exit 1;;
    esac
    git remote add "$REMOTE" git@github.com:bitcoin-core/secp256k1.git &> /dev/null
    git fetch "$REMOTE" &> /dev/null
}

range() {
    RANGESTART_COMMIT=$(git merge-base "$REMOTE_BRANCH" "$LOCAL_BRANCH")
    RANGEEND_COMMIT=$(git rev-parse "$REMOTE_BRANCH")
    if [ "$#" = 1 ]; then
        RANGEEND_COMMIT=$1
    fi

    COMMITS=$(git --no-pager log --oneline --merges "$RANGESTART_COMMIT".."$RANGEEND_COMMIT")
    COMMITS=$(echo "$COMMITS" | tac | awk '{ print $1 }' ORS=' ')
    echo "Merging $COMMITS. Continue with y"
    read -r yn
    case $yn in
        [Yy]* ) ;;
        * ) exit 1;;
    esac
}

# Process -b <branch> argument
while getopts "b:" opt; do
  case $opt in
    b)
      LOCAL_BRANCH=$OPTARG
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      ;;
  esac
done

# Shift off the processed options
shift $((OPTIND -1))

if [ "$#" -lt 1 ]; then
    help
fi

case $1 in
    range)
        shift
        setup
        range "$@"
        REPRODUCE_COMMAND="$0 -b $LOCAL_BRANCH range $RANGEEND_COMMIT"
        ;;
    select)
        shift
        setup
        COMMITS=$*
        REPRODUCE_COMMAND="$0 -b $LOCAL_BRANCH select $@"
        ;;
    help)
        help
        ;;
    *)
        help
esac

TITLE="Upstream PRs"
BODY=""
for COMMIT in $COMMITS
do
    PRNUM=$(git log -1 "$COMMIT" --pretty=format:%s | sed s/'Merge \(bitcoin-core\/secp256k1\)\?#\([0-9]*\).*'/'\2'/)
    TITLE="$TITLE $PRNUM,"
    BODY=$(printf "%s\n%s" "$BODY" "$(git log -1 "$COMMIT" --pretty=format:%s | sed s/'Merge \(bitcoin-core\/secp256k1\)\?#\([0-9]*\)'/'[bitcoin-core\/secp256k1#\2]'/)")
done
# Remove trailing ","
TITLE=${TITLE%?}
BODY=$(printf "%s\n\n%s\n%s" "$BODY" "This PR can be recreated with \`$REPRODUCE_COMMAND\`." "Tip: Use \`git show --remerge-diff\` to show the changes manually added to the merge commit.")

echo "-----------------------------------"
echo "$TITLE"
echo "-----------------------------------"
echo "$BODY"
echo "-----------------------------------"
# Create branch from PR commit and create PR
git checkout "$LOCAL_BRANCH"
git pull --autostash
git checkout -b temp-merge-"$PRNUM"

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
gh pr create -t '$TITLE' -b '$BODY' --web
# Remove temporary branch
git checkout "$LOCAL_BRANCH"
git branch -D temp-merge-"$PRNUM"
EOT
chmod +x "$FNAME"
echo Run "$FNAME" after solving the merge conflicts

git merge --no-edit -m "Merge commits '$COMMITS' into temp-merge-$PRNUM" $COMMITS
