{
  # keep-sorted start
  cmake,
  lib,
  src,
  stdenv,
  # keep-sorted end
}:
stdenv.mkDerivation {
  pname = "dobby";

  version = "0-unstable-2023-03-29";

  inherit src;

  nativeBuildInputs = [cmake];

  cmakeFlags = [
    # keep-sorted start
    "-DDOBBY_BUILD_EXAMPLE=OFF"
    "-DDOBBY_BUILD_TEST=OFF"
    "-DPlugin.SymbolResolver=OFF"
    # keep-sorted end
  ];

  installPhase = ''
    runHook preInstall

    install -D --mode=444 libdobby.so $out/lib/libdobby.so
    install -D --mode=444 $src/include/dobby.h $out/include/dobby.h

    runHook postInstall
  '';

  meta = {
    description = "Lightweight, multi-platform hook framework";
    homepage = "https://github.com/jmpews/Dobby";

    license = lib.licenses.asl20;

    platforms = lib.platforms.linux;
  };
}
