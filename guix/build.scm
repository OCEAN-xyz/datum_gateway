(use-modules (guix packages)
             (guix gexp)
             (guix git-download)
             (guix utils)
             ((guix licenses) #:prefix license:)
             (guix build-system)
             (guix build-system cmake)
             (gnu packages base)
             (gnu packages crypto)
             (gnu packages curl)
             (gnu packages elf)
             (gnu packages gnunet)
             (gnu packages pkg-config)
             (gnu packages web)
             (ice-9 match)
             (ice-9 popen)
             (ice-9 regex)
             (ice-9 textual-ports))

(define %source-dir
  (dirname (dirname (canonicalize-path (current-filename)))))

(define %git-checkout?
  (file-exists? (string-append %source-dir "/.git")))

(define (git . args)
  "Run git with ARGS in %source-dir.  Return its trimmed standard output, or
#f if it exited with a non-zero status."
  (let* ((port (with-error-to-file "/dev/null"
                 (lambda ()
                   (apply open-pipe* OPEN_READ "git" "-C" %source-dir args))))
         (output (string-trim-both (get-string-all port))))
    (and (zero? (status:exit-val (close-pipe port)))
         output)))

(define %head-commit
  (and %git-checkout?
       (or (git "rev-parse" "HEAD")
           (error "could not run 'git rev-parse HEAD' in" %source-dir))))

(define %dirty?
  (and %head-commit
       (not (git "diff" "--quiet" "HEAD" "--"))))

(define %release-tag
  (and %head-commit
       (not %dirty?)
       (git "describe" "--exact-match" "--abbrev=0" "HEAD")))

(define %git-version-header
  (string-append
   "#define GIT_COMMIT_HASH \""
   (cond ((not %head-commit) "UNKNOWN_GIT_HASH")
         (%dirty? (string-append %head-commit "+"))
         (else %head-commit))
   "\"\n"
   (if %release-tag
       (string-append "#define BUILD_GIT_TAG \"" %release-tag "\"\n")
       "")))

(define %base-version
  (let ((m (string-match "project\\(DATUM VERSION ([0-9.]+)"
                         (call-with-input-file
                             (string-append %source-dir "/CMakeLists.txt")
                           get-string-all))))
    (if m
        (match:substring m 1)
        (error "could not find the project version in CMakeLists.txt"))))

(define %version
  (if (or %release-tag (not %head-commit))
      %base-version
      (string-append %base-version "-" (string-take %head-commit 12)
                     (if %dirty? "-dirty" ""))))

(define %glibc glibc-2.35)

(define (with-glibc bs)
  "Return a variant of BS, a build system, that builds against %glibc."
  (build-system
    (inherit bs)
    (lower (lambda args
             (let ((lowered (apply (build-system-lower bs) args)))
               (bag
                 (inherit lowered)
                 (build-inputs
                  (map (match-lambda
                         (("libc" . _) `("libc" ,%glibc))
                         (("libc:static" . _) `("libc:static" ,%glibc "static"))
                         (input input))
                       (bag-build-inputs lowered)))))))))

(define (static-library p . configure-flags)
  "Return P built as a static library only, against %glibc, with
CONFIGURE-FLAGS and without its inputs."
  (package/inherit p
    (name (string-append (package-name p) "-static"))
    (build-system (with-glibc (package-build-system p)))
    (arguments
     (substitute-keyword-arguments (package-arguments p)
       ((#:configure-flags _ #~'())
        #~(list "--disable-shared" "--enable-static" #$@configure-flags))
       ;; Already tested by Guix, and slow on arm64 under emulation.
       ((#:tests? _ #t) #f)))
    (inputs '())
    (propagated-inputs '())))

(define curl-static
  (static-library curl
                  "--without-ssl" "--without-zlib" "--without-brotli"
                  "--without-zstd" "--without-libpsl" "--without-libidn2"
                  "--without-nghttp2" "--without-gssapi" "--without-libssh2"
                  "--disable-ldap"))

(define libmicrohttpd-static
  (static-library libmicrohttpd "--disable-https" "--disable-curl"))

(define (system-dynamic-linker)
  "Return the file name of the dynamic linker on common distributions."
  (cond ((target-x86-64?) "/lib64/ld-linux-x86-64.so.2")
        ((target-aarch64?) "/lib/ld-linux-aarch64.so.1")
        (else (error "unsupported system" (%current-system)))))

(package
  (name "datum-gateway")
  (version %version)
  (source (local-file %source-dir "datum-gateway-checkout"
                      #:recursive? #t
                      ;; Only tracked files: build trees, local configs and
                      ;; other untracked files must not leak into the build.
                      #:select? (if %git-checkout?
                                    (git-predicate %source-dir)
                                    (const #t))))
  (build-system (with-glibc cmake-build-system))
  (arguments
   (list
    #:modules '((guix build cmake-build-system)
                (guix build gremlin)
                (guix build utils)
                (srfi srfi-1))
    ;; Same optimisation level as the upstream Dockerfile.
    #:build-type "Release"
    #:configure-flags
    #~(list "-DENABLE_API=ON"
            (string-append "-DCMAKE_EXE_LINKER_FLAGS=-static-libgcc "
                           "-Wl,--dynamic-linker="
                           #$(file-append %glibc "/lib/"
                                          (basename (system-dynamic-linker)))
                           " -Wl,-rpath," #$(file-append %glibc "/lib")))
    #:phases
    #~(modify-phases %standard-phases
        (add-after 'unpack 'use-fixed-build-info
          (lambda _
            (call-with-output-file "guix_git_version.h"
              (lambda (port)
                (display #$%git-version-header port)))
            (call-with-output-file "cmake/script/GenerateBuildInfo.cmake"
              (lambda (port)
                (display "configure_file(\"${SOURCE_DIR}/guix_git_version.h\" \
\"${BUILD_INFO_HEADER_PATH}\" COPYONLY)\n"
                         port)))))
        (replace 'check
          (lambda* (#:key tests? #:allow-other-keys)
            (when tests?
              (invoke "./datum_gateway" "--test"))))
        ;; Runs last, after the binary has been stripped: the output is
        ;; bin/datum_gateway alone, which uses the system's glibc.
        (add-after 'compress-documentation 'keep-only-binary
          (lambda _
            (let ((binary (string-append #$output "/bin/datum_gateway")))
              ;; The build directory is on another file system, so copy.
              (copy-file binary "datum_gateway.installed")
              (delete-file-recursively #$output)
              (invoke "patchelf" "--set-interpreter" #$(system-dynamic-linker)
                      "--remove-rpath" "datum_gateway.installed")
              ;; patchelf leaves the old RUNPATH in the string table.
              (remove-store-references "datum_gateway.installed")
              (let ((unexpected (remove (lambda (library)
                                          (or (string-prefix? "libc." library)
                                              (string-prefix? "libm." library)
                                              (string=? library
                                                        #$(basename
                                                           (system-dynamic-linker)))))
                                        (file-needed "datum_gateway.installed"))))
                (unless (null? unexpected)
                  (error "datum_gateway links to libraries other than glibc:"
                         unexpected)))
              (mkdir-p (dirname binary))
              (copy-file "datum_gateway.installed" binary)
              (chmod binary #o555)))))))
  (native-inputs (list patchelf pkg-config))
  (inputs (list curl-static
                (static-library jansson)
                libmicrohttpd-static
                (static-library libsodium)))
  (home-page "https://github.com/OCEAN-xyz/datum_gateway")
  (synopsis "Decentralized Alternative Templates for Universal Mining")
  (description
   "The DATUM Gateway is a server providing solo mining capabilities for
Bitcoin miners, including both non-pooled and pooled solo mining using the
DATUM protocol.  It builds block templates from a local Bitcoin node and
serves work to miners over Stratum.")
  (license license:expat))
