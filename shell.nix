{ pkgs ? import <nixpkgs> {}}:

pkgs.mkShell {
  nativeBuildInputs = [
    pkgs.delve
    pkgs.go
    pkgs.gopls
  ];
}
