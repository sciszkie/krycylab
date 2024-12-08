import subprocess

# Uruchomienie notebooka (wykonanie kodu w notebooku)
subprocess.run(
    ["jupyter", "nbconvert", "--to", "notebook", "--execute", "--inplace", "nb.ipynb"],
    check=True
)

# Konwersja na PDF po zakończeniu
subprocess.run(
    ["jupyter", "nbconvert", "--to", "pdf", "nb.ipynb"],
    check=True
)