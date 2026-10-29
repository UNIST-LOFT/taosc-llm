;;; Local checkout recipe; no remote taosc-llm release is assumed.

(use-modules (gnu packages check)
             (gnu packages commencement)
             (gnu packages patchutils)
             (gnu packages python-build)
             (guix build-system pyproject)
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
                           "src" "src/taosc_llm" "tests"))
        (string=? relative "src/taosc_llm/runtime.c")
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
                 (setenv "E9COMPILE" (string-append #$e9patch "/bin/e9compile")))))))
  (native-inputs (list python-setuptools python-pytest gcc-toolchain e9patch))
  (propagated-inputs (list local-binradar))
  (home-page "https://github.com/UNIST-LOFT/binradar")
  (synopsis "Build manual generic guards from prepared Taosc metadata")
  (description
   "This command compiles one manually supplied generic guard into fixed and
BinRadar-selectable binaries using prepared patch addresses and an original
binary.  It neither discovers patch locations nor verifies the repair.")
  (license license:gpl2))
