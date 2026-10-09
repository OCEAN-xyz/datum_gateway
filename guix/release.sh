set -eu

cd "$(dirname "$0")/.."

out_dir=dist
archives=

guix_pinned() {
	guix time-machine -C guix/channels.scm -- "$@"
}

mkdir -p "$out_dir"

for arch in amd64 arm64; do
	case $arch in
		amd64) system=x86_64-linux ;;
		arm64) system=aarch64-linux ;;
	esac

	echo "Building $arch ($system)..." >&2
	package=$(guix_pinned build --system="$system" -f guix/build.scm)
	version=${package#*-datum-gateway-}

	echo "Archiving $arch..." >&2
	archive=datum_gateway-$version-$arch.tar.gz
	guix_pinned shell --pure tar gzip -- \
		tar --create --file="$out_dir/$archive" \
		--use-compress-program='gzip -9n' --format=gnu --sort=name \
		--mtime=@1 --owner=0 --group=0 --numeric-owner --mode=u+w \
		--directory="$package/bin" datum_gateway
	archives="$archives $archive"
done

(cd "$out_dir" && sha256sum $archives > SHA256SUMS)

echo "Wrote to $out_dir/:" >&2
cat "$out_dir/SHA256SUMS" >&2
