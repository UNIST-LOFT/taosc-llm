;;; Local, hash-pinned Linux x86-64 static analysis dependencies.
;;; Official binary distributions retain their bundled license material.
(use-modules (gnu packages bash)
             (gnu packages elf)
             (gnu packages gcc)
             (gnu packages java)
             (gnu packages linux)
             (gnu packages compression))

(define analysis-jdk (gexp-input openjdk21 "jdk"))

(define analysis-node-source
  (origin
    (method url-fetch)
    (uri "https://nodejs.org/dist/v26.12.1/node-v26.12.1-linux-x64.tar.xz")
    (sha256 (base32 "1gcv0xmvr38chlyzr92q69bkpzpril8xqfpz7ks2dip1fkab4w31"))))

;; Publisher asset and SHA-256 are recorded at the official 12.1 release:
;; https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1_build
(define ghidra-source
  (origin
    (method url-fetch)
    (uri "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1_build/ghidra_12.1_PUBLIC_20260513.zip")
    (sha256 (base32 "00pklv4dls74xphbcklrsm6dw6igb4chx46fbwcclhcgyjxvqp5a"))))

(define analysis-node
  (package
    (name "taosc-llm-node")
    (version "26.12.1")
    (source analysis-node-source)
    (build-system trivial-build-system)
    (arguments
     (list #:modules '((guix build utils))
           #:builder
           #~(begin
               (use-modules (guix build utils))
               (setenv "PATH" (string-append #$tar "/bin:" #$xz "/bin"))
               (mkdir-p "unpack")
               (invoke "tar" "xf" #$analysis-node-source "--directory" "unpack" "--strip-components=1")
               (install-file "unpack/bin/node" (string-append #$output "/libexec"))
               (chmod (string-append #$output "/libexec/node") #o755)
               (install-file "unpack/LICENSE" (string-append #$output "/share/licenses/node"))
               ;; Adding RUNPATH with patchelf 0.18 moves this large executable's
               ;; dynamic strings into overlapping LOAD segments. Relocate only
               ;; its interpreter; a private wrapper supplies the exact libraries.
               (invoke #$(file-append patchelf "/bin/patchelf")
                       "--set-interpreter" #$(file-append glibc "/lib/ld-linux-x86-64.so.2")
                       (string-append #$output "/libexec/node"))
               (mkdir-p (string-append #$output "/bin"))
               (call-with-output-file (string-append #$output "/bin/node")
                 (lambda (port)
                   (format port "#!~a/bin/sh~%export LD_LIBRARY_PATH=~a/lib:~a/lib~%exec ~a/libexec/node \"$@\"~%"
                           #$bash-minimal #$(gexp-input gcc-14 "lib") #$glibc #$output)))
               (chmod (string-append #$output "/bin/node") #o555))))
    (supported-systems '("x86_64-linux"))
    (home-page "https://nodejs.org")
    (synopsis "Pinned Node runtime for Pi and REA")
    (description "Official Node 26.12.1 runtime, relocated to the Guix dependency closure. No npm CLI or runtime installation is used.")
    (license license:expat)))

(define ghidra-runtime
  (package
    (name "taosc-llm-ghidra")
    (version "12.1")
    (source ghidra-source)
    (build-system trivial-build-system)
    (arguments
     (list #:modules '((guix build utils))
           #:builder
           #~(begin
               (use-modules (guix build utils))
               (invoke #$(file-append unzip "/bin/unzip") "-q" #$ghidra-source)
               (let ((destination (string-append #$output "/share/ghidra")))
                 (mkdir-p (dirname destination))
                 (copy-recursively "ghidra_12.1_PUBLIC" destination)
                 (let ((scripts (find-files (string-append destination "/support")
                                            "(\\.sh|analyzeHeadless)$")))
                   (substitute* scripts
                     (("/usr/bin/env bash") #$(file-append bash-minimal "/bin/bash")))
                   (for-each (lambda (script) (chmod script #o555)) scripts))
                 ;; A private PATH also covers launch.sh's expr, uname and
                 ;; analyzeHeadless's readlink; neither launcher needs host tools.
                 (substitute* (string-append destination "/support/launch.sh")
                   (("umask 027")
                    (string-append "export PATH=" #$analysis-jdk "/bin:"
                                   #$coreutils "/bin:"
                                   #$bash-minimal "/bin\nexport JAVA_HOME="
                                   #$analysis-jdk "\numask 027")))
                 (for-each
                  (lambda (relative)
                    (let* ((binary (string-append destination "/" relative))
                           (real (string-append binary ".real")))
                      ;; As with Node, adding RUNPATH corrupts overlapping LOAD
                      ;; pages in the official non-PIE decompiler. Keep dynamic
                      ;; strings untouched and bind libraries in a private wrapper.
                      (rename-file binary real)
                      (chmod real #o755)
                      (invoke #$(file-append patchelf "/bin/patchelf")
                              "--set-interpreter" #$(file-append glibc "/lib/ld-linux-x86-64.so.2")
                              real)
                      (call-with-output-file binary
                        (lambda (port)
                          (format port "#!~a/bin/sh~%export LD_LIBRARY_PATH=~a/lib:~a/lib~%exec ~a \"$@\"~%"
                                  #$bash-minimal #$(gexp-input gcc-14 "lib") #$glibc real)))
                      (chmod binary #o555)))
                  '("Ghidra/Features/Decompiler/os/linux_x86_64/decompile"
                    "Ghidra/Features/Decompiler/os/linux_x86_64/sleigh"
                    "Ghidra/Features/FileFormats/os/linux_x86_64/lzfse"
                    "GPL/DemanglerGnu/os/linux_x86_64/demangler_gnu_v2_24"
                    "GPL/DemanglerGnu/os/linux_x86_64/demangler_gnu_v2_41"))))))
    (supported-systems '("x86_64-linux"))
    (home-page "https://ghidra-sre.org")
    (synopsis "Pinned Ghidra headless analysis distribution")
    (description "The official Ghidra 12.1 release, with the Linux x86-64 decompiler relocated for Guix. Analysis runs with private writable projects outside the store.")
    (license license:asl2.0)))

(define rea-directory (string-append package-directory "/thirdparty/rea"))
(define rea-tarballs (primitive-load (string-append rea-directory "/npm-closure.scm")))
(define rea-runtime
  (package
    (name "taosc-llm-rea")
    (version "6.8.0")
    (source #f)
    (build-system trivial-build-system)
    (arguments
     (list #:modules '((guix build utils))
           #:builder
           #~(begin
               (use-modules (guix build utils))
               (setenv "PATH" (string-append #$tar "/bin:" #$gzip "/bin"))
               (let ((root (string-append #$output "/share/rea")))
                 (mkdir-p root)
                 (copy-file #$(local-file (string-append rea-directory "/package.json")) (string-append root "/package.json"))
                 (copy-file #$(local-file (string-append rea-directory "/package-lock.json")) (string-append root "/package-lock.json"))
                 (for-each
                  (lambda (relative archive)
                    (let ((destination (string-append root "/" relative)))
                      (mkdir-p destination)
                      (invoke "tar" "--extract" "--gzip" "--file" archive
                              "--directory" destination "--strip-components=1" "--no-same-owner")))
                  '#$(map car rea-tarballs) (list #$@(map cadr rea-tarballs)))
                 (mkdir-p (string-append #$output "/bin"))
                 ;; REA inspects child ownership with procps ps before spawning Ghidra.
                 (call-with-output-file (string-append #$output "/bin/rea")
                   (lambda (port)
                     (format port "#!~a/bin/sh~%export PATH=~a/bin:~a/bin:~a/bin:~a/bin:~a/bin~%export JAVA_HOME=~a~%export GHIDRA_INSTALL_DIR=~a/share/ghidra~%exec ~a/bin/node ~a/node_modules/rea-agents/scripts/rea.mjs \"$@\"~%"
                             #$bash-minimal #$analysis-node #$analysis-jdk
                             #$coreutils #$procps #$bash-minimal #$analysis-jdk
                             #$ghidra-runtime #$analysis-node root)))
                 (chmod (string-append #$output "/bin/rea") #o555)))))
    (home-page "https://github.com/morluto/rea")
    (synopsis "Pinned REA runtime for host-owned static analysis")
    (description "REA 6.8.0 and its locked nonoptional npm runtime dependencies, assembled without lifecycle scripts or optional Frida installation. Taosc exposes only prepared static views to models, not REA's general command surface.")
    ;; Includes the nonoptional locked dependency licenses, not optional Frida.
    (license (list license:expat license:asl2.0 license:isc license:bsd-2
                   license:bsd-3 license:zlib license:blue-oak1.0.0
                   license:lgpl3+))))
