;;; Local checkout recipe; no remote taosc-llm release is assumed.

(use-modules (gnu packages check)
             (gnu packages compression)
             (gnu packages node)
             (gnu packages base)
             (gnu packages commencement)
             (gnu packages patchutils)
             (gnu packages python-build)
             (guix build-system pyproject)
             (guix build-system trivial)
             (guix download)
             (guix gexp)
             ((guix licenses) #:prefix license:)
             (guix packages)
             (guix utils)
             (loftix fuzzing)
             (srfi srfi-1)
             (srfi srfi-13))

(define package-directory (canonicalize-path (dirname (current-filename))))
(define checkout-directory
  (canonicalize-path (string-append package-directory "/../..")))

;; Only these three reviewed files enter the SDK derivation. The development
;; npm cache and node_modules are never source inputs.
(define sdk-directory (string-append package-directory "/thirdparty/pi"))
(define sdk-tarballs
  (primitive-load (string-append sdk-directory "/npm-closure.scm")))

(define pi-sdk
  (package
    (name "taosc-llm-pi-sdk")
    (version "1.4.0")
    (source #f)
    (build-system trivial-build-system)
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils))
          (setenv "PATH" (string-append #$tar "/bin:" #$gzip "/bin"))
          (mkdir-p #$output)
          (copy-file #$(local-file (string-append sdk-directory "/package.json"))
                     (string-append #$output "/package.json"))
          (copy-file #$(local-file (string-append sdk-directory "/package-lock.json"))
                     (string-append #$output "/package-lock.json"))
          ;; The lock's complete hoisted/nested layout is explicit. Extract only:
          ;; no npm resolution, lifecycle hooks, native builds or network calls.
          (for-each
           (lambda (relative archive)
             (let ((destination (string-append #$output "/" relative)))
               (mkdir-p destination)
               (invoke "tar" "--extract" "--gzip" "--file" archive
                       "--directory" destination "--strip-components=1"
                       "--no-same-owner")))
           '#$(map car sdk-tarballs)
           (list #$@(map cadr sdk-tarballs))))))
    (home-page "https://github.com/earendil-works/pi")
    (synopsis "Pinned offline Pi SDK dependency tree")
    (description
     "The exact npm lockfile dependency tree for Pi SDK 1.4.0, assembled from
integrity-bound registry tarballs without running package lifecycle scripts.
This package supplies SDK imports, not npm CLI executable shims.")
    (license (list license:expat license:asl2.0 license:isc license:bsd-3
                   license:bsd-0 license:unlicense license:blue-oak1.0.0))))

(define (source-file? file stat)
  (not (or (member (basename file)
                   '(".git" ".venv" ".env" "build" "dist" "__pycache__"
                     ".pytest_cache" ".ruff_cache" ".mypy_cache"))
           (string-prefix? ".env." (basename file))
           (string-suffix? ".egg-info" file)
           (string-suffix? ".pyc" file))))

;; Guix sources are world-readable. Never recursively copy a development
;; directory: it can acquire credentials/workdirs independently of this recipe.
(define (taosc-source-file? file stat)
  (let ((relative (if (string=? file package-directory)
                      ""
                      (string-drop file (+ 1 (string-length package-directory))))))
    (or (member relative '("" "pyproject.toml" "README.md" "LICENSE" "uv.lock"
                           "src" "src/taosc_llm" "tests"
                           "src/taosc_llm/pi" "src/taosc_llm/prompts"))
        (member relative '("src/taosc_llm/runtime.c"
                           "src/taosc_llm/pi/adapter.mjs"
                           "src/taosc_llm/prompts/system.txt"))
        (and (or (string-prefix? "src/taosc_llm/" relative)
                 (string-prefix? "tests/" relative))
             (string-suffix? ".py" relative)))))

;; The pinned Loftix package supplies the native dependency closure, but this
;; stage uses the current checkout's parser, metadata API and runtime resources.
;; Its Python inputs must propagate: BinRadar normally wraps only its own CLIs.
(define local-binradar
  (package
    (inherit binradar)
    (source
     (local-file checkout-directory "binradar-local-source"
       #:recursive? #t
       #:select? (lambda (file stat)
                   (or (string=? file checkout-directory)
                       (let ((relative
                              (string-drop file
                                           (+ 1 (string-length checkout-directory)))))
                         (and (source-file? file stat)
                              (or (member relative
                                          '("pyproject.toml" "README.md" "LICENSE"
                                            "binradar" "benchmarks"
                                            "benchmarks/loftix"
                                            "benchmarks/loftix/brpatch.c"
                                            "benchmarks/loftix/brpatch-cached.c"
                                            "utils" "utils/coverage_tracer.py"))
                                  (string-prefix? "binradar/" relative))))))))
    (arguments
     (substitute-keyword-arguments (package-arguments binradar)
       ((#:phases phases)
        #~(modify-phases #$phases
            (add-after 'patch-paths 'patch-current-resource-paths
              (lambda _
                (substitute* "binradar/paths.py"
                  (("^BRPATCH_SOURCE = .*\n")
                   (string-append "BRPATCH_SOURCE = Path(\"" #$output
                                  "/share/binradar/brpatch.c\")\n"))
                  (("^BRPATCH_CACHED_SOURCE = .*\n")
                   (string-append "BRPATCH_CACHED_SOURCE = Path(\"" #$output
                                  "/share/binradar/brpatch-cached.c\")\n"))
                  (("_guix_e9_bin_dir\\(\\) / name")
                   (string-append "Path(\"" #$e9patch "/bin\") / name")))))
            (add-after 'install 'install-runtime-resources
              (lambda _
                (install-file "benchmarks/loftix/brpatch.c"
                              (string-append #$output "/share/binradar"))
                (install-file "benchmarks/loftix/brpatch-cached.c"
                              (string-append #$output "/share/binradar"))))))))
    (propagated-inputs
     (append (package-propagated-inputs binradar)
             (filter (lambda (input)
                       (string-prefix? "python-" (car input)))
                     (package-inputs binradar))
             (list (list "python-pytest" python-pytest))))))

(package
  (name "taosc-llm")
  (version "0.1.0")
  (source (local-file package-directory "taosc-llm-source"
            #:recursive? #t #:select? taosc-source-file?))
  (build-system pyproject-build-system)
  (arguments
   (list #:phases
         #~(modify-phases %standard-phases
             (add-before 'check 'enable-native-tests
               (lambda _
                 (setenv "E9TOOL" (string-append #$e9patch "/bin/e9tool"))
                 (setenv "E9COMPILE" (string-append #$e9patch "/bin/e9compile"))
                 (setenv "TAOSC_LLM_NODE" (string-append #$node "/bin/node"))
                 (setenv "TAOSC_LLM_PI_SDK_ROOT" #$pi-sdk)))
             (add-after 'install 'install-sdk-root
               (lambda _
                 (mkdir-p (string-append #$output "/share/taosc-llm"))
                 (symlink #$pi-sdk
                          (string-append #$output "/share/taosc-llm/pi-sdk"))))
             (add-after 'wrap 'wrap-pi-runtime
               (lambda _
                 (for-each
                  (lambda (program)
                    (wrap-program (string-append #$output "/bin/" program)
                      `("PATH" prefix (,(string-append #$gcc-toolchain "/bin")
                                        ,(string-append #$binutils "/bin")))
                      `("C_INCLUDE_PATH" = (,(string-append #$gcc-toolchain "/include")))
                      `("LIBRARY_PATH" = (,(string-append #$gcc-toolchain "/lib")))
                      `("TAOSC_LLM_NODE" = (,(string-append #$node "/bin/node")))
                      `("TAOSC_LLM_PI_SDK_ROOT" =
                        (,(string-append #$output "/share/taosc-llm/pi-sdk")))))
                  '("taosc-llm" "taosc-llm-fixture")))))))
  (inputs (list node pi-sdk gcc-toolchain binutils))
  (native-inputs (list python-setuptools python-pytest gcc-toolchain e9patch))
  (propagated-inputs (list local-binradar))
  (home-page "https://github.com/UNIST-LOFT/binradar")
  (synopsis "Synthesize and build generic guards from prepared Taosc metadata")
  (description
   "This command proposes a generic guard with an isolated Pi SDK session, or
accepts a manual predicate, and compiles fixed and BinRadar-selectable binaries.
It uses caller-prepared evidence and explicit provider configuration.  It neither
discovers patch locations nor supplies BinRadar repair verification.")
  (license license:gpl2))
