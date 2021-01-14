#!/bin/bash

set -eou pipefail

help() {
    echo "$0 range [end]"
    echo "    merges every merge commit missing merge commit."
    echo "    If the optional [end] commit is provided, only merges up to [end]."
    echo
    echo "$0 select <commit> ... <commit>"
    echo "    merges every selected merge commit"
    echo
    echo "This tool creates a branch and a script that can be executed to create the"
    echo "PR automatically. The script requires the github-cli tool (aka gh)."
    echo ""
    echo "Tip: \`git log --oneline upstream/master --merges\` shows merge commits."
    exit 1
}

if [ "$#" -lt 1 ]; then
    help
fi

REMOTE=upstream
REMOTE_BRANCH=$REMOTE/master
# Makes sure you have a remote "upstream" that is up-to-date
setup() {
    ret=0
    git fetch $REMOTE &> /dev/null || ret=$?
    if [ ${ret} == 0 ]; then
        return
    fi
    echo "Adding remote \"$REMOTE\" with URL git@github.com:bitcoin-core/secp256k1.git. Continue with y"
    read -r yn
    case $yn in
        [Yy]* ) ;;
        * ) exit 1;;
    esac
    git remote add $REMOTE git@github.com:bitcoin-core/secp256k1.git &> /dev/null
    git fetch $REMOTE &> /dev/null
}

range() {
    RANGESTART_COMMIT=$(git merge-base $REMOTE_BRANCH master)
    RANGEEND_COMMIT=$REMOTE_BRANCH
    if [ "$#" = 1 ]; then
        RANGEEND_COMMIT=$1
    fi

    COMMITS=$(git --no-pager log --oneline "$REMOTE_BRANCH" --merges "$RANGESTART_COMMIT".."$RANGEEND_COMMIT")
    COMMITS=$(echo "$COMMITS" | tac | awk '{ print $1 }' ORS=' ')
    echo "Merging $COMMITS. Continue with y"
    read -r yn
    case $yn in
        [Yy]* ) ;;
        * ) exit 1;;
    esac
}

case $1 in
    range)
        shift
        setup
        range "$@"
        ;;
    select)
        shift
        setup
        COMMITS=$*
        ;;
    help)
        help
        ;;
    *)
        help
esac

TITLE="Upstream PRs "
BODY=""
for COMMIT in $COMMITS
do
    PRNUM=$(git log -1 "$COMMIT" --pretty=format:%s | sed s/'Merge #\([0-9]*\).*'/'\1'/)
    TITLE="$TITLE #$PRNUM"
    BODY=$(printf "%s\n%s" "$BODY" "$(git log -1 "$COMMIT" --pretty=format:%s | sed s/'Merge #\([0-9]*\)'/'[upstream PR #\1]'/)")
done

BODY=$(printf "%s\n\n%s" "$BODY" "This PR was automatically created with \\\`$0 $*\\\`.")

echo "-----------------------------------"
echo "$TITLE"
echo "-----------------------------------"
echo "$BODY"
echo "-----------------------------------"
# Create branch from PR commit and create PR
git checkout master
git pull
git checkout -b temp-merge-"$PRNUM"

BASEDIR=$(dirname "$0")
FNAME=$BASEDIR/gh-pr-create.sh
cat <<EOT > "$FNAME"
#!/bin/sh
gh pr create -t "$TITLE" -b "$BODY" --web
# Remove temporary branch
git checkout master
git branch -D temp-merge-"$PRNUM"
EOT
chmod +x "$FNAME"
echo Run "$FNAME" after solving the merge conflicts

git merge --no-edit -m "Merge commits '$COMMITS' into temp-merge-$PRNUM" $COMMITS
