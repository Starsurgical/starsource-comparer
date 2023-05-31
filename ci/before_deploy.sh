# This script takes care of building your crate and packaging it for release

set -ex

main() {
    local src=$(pwd) \
          stage=

    case $TRAVIS_OS_NAME in
        linux)
            stage=$(mktemp -d)
            ;;
        osx)
            stage=$(mktemp -d -t tmp)
            ;;
    esac

    test -f Cargo.lock || cargo generate-lockfile

    cargo rustc --bin starsource-comparer --target $TARGET --release

    cp target/$TARGET/release/starsource-comparer $stage/

    cd $stage
    tar cJf $src/$CRATE_NAME-$TRAVIS_TAG-$TARGET.tar.xz *
    cd $src

    rm -rf $stage
}

main
