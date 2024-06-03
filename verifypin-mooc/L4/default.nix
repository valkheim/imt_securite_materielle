with import <nixpkgs> {};


let
     pkgs = import (builtins.fetchGit {
        # Descriptive name to make the store path easier to identify                
        name = "pinned_nix_packages";                                                 
        url = "https://github.com/nixos/nixpkgs/";                       
        ref = "nixos-23.11";                     
        rev = "d65bceaee0fb1e64363f7871bc43dc1c6ecad99f";                                           
    }) {};
                                                                   
in

# Make a new "derivation" that represents our shell
stdenv.mkDerivation {
  name = "scafia";

  # The packages in the `buildInputs` list will be added to the PATH in our shell
  buildInputs = with pkgs.python311Packages; [
    pkgs.gcc-arm-embedded


    pip
    pyelftools
    numpy
    termcolor
    unicorn
    Keras
    tqdm
    tensorflow
  ];
}