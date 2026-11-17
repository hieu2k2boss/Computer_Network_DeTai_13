### Cài MiKTeX để build latex trên Win
cd template-tieu-luan-latext-tham-khao
``` cmd
latexmk -pdf -interaction=nonstopmode -halt-on-error -synctex=0 -emulate-aux-dir -outdir=../outputs -auxdir=.latex-build Nhom-14-De-tai-7TT.tex
```