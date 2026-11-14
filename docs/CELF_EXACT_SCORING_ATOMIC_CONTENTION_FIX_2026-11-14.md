# CELF exact-batch GPU scoring: per-rule counters and compaction — 2026-11-14

## Cel

Zachować dokładne gainy CELF i `np.unique`, ale uniknąć zarówno jednego
wspólnego licznika atomowego, jak i transferu gęstej macierzy
`n_rules x n_words` z komórkami dla nietrafionych par.

## Trzy etapy

1. **GPU — exact scoring z licznikami per reguła.**
   `score_exact_batch_kernel` ma osobny licznik `rule_hit_counts[rule_idx]`.
   Trafienie jest dopisywane do segmentu `rule_idx * words_per_rule_cap`.
   Segment ma pojemność równą maksymalnemu rozmiarowi word-chunka; jedna reguła
   może zapisać najwyżej jedno trafienie na słowo, więc nie może go przepełnić.
   Nie istnieje współdzielony licznik dla całego batcha.

2. **GPU — kompakcja trafień.**
   Host odczytuje mały wektor liczników, wylicza prefiksowe offsety i przesyła
   je na GPU. `compact_exact_hits_kernel` uruchamia work-item wyłącznie dla
   rzeczywistych trafień. Każdy work-item wyszukuje segment źródłowy przez
   prefiksy i kopiuje slot do zwartego bufora. Nie powstaje bufor identyfikatorów
   reguł.

3. **CPU — jeden zbiorczy odczyt wyników.**
   Dla niepustego word-chunka CPU wykonuje jeden D2H odczyt zwartego strumienia
   slotów. Mały odczyt liczników jest osobnym transferem sterującym potrzebnym
   do zbudowania offsetów i rozmiaru kompaktowanego wyniku. CPU rozdziela
   strumień według liczników, zachowuje sloty do końcowego `np.unique` osobno
   dla każdej reguły i przez wszystkie chunki.

## Niezmienniki CELF

- Każda reguła nadal otrzymuje dokładny zbiór aktywnych slotów celu.
- Duplikaty slotów w ramach reguły i pomiędzy word-chunkami są usuwane przez
  istniejące `np.unique`.
- Gain, test aktywności, priorytety, kolejność wyboru i tie-break CELF nie są
  zmieniane.
- `apply_winner_and_clear` nadal otrzymuje dokładną listę unikalnych slotów
  zwycięskiej reguły.

## Profilowanie

`exact-result D2H` raportuje liczbę zbiorczych odczytów kompaktowanych slotów,
liczbę kernel launchy compaction, bajty danych wynikowych oraz liczbę i rozmiar
małych odczytów liczników. W `gpu_dispatches` uwzględniane są oba kernele:
scoring oraz compaction.

## Weryfikacja

- `pytest -q tests/ranker_suite`: **154 passed, 1 skipped**.
- Skipped: integracyjny test GPU, ponieważ środowisko nie ma rzeczywistego
  runtime OpenCL.
- Wygenerowane źródło OpenCL przechodzi
  `clang -x cl -cl-std=CL1.2 -fsyntax-only`.
- Nieaktualne testy dawnego modułu licencjonowania zostały usunięte z bieżącej
  wersji projektu; licencjonowanie nie należy już do tego wydania.
- Nie wykonano benchmarku na karcie docelowej; przyspieszenie wymaga pomiaru
  na tym samym zbiorze danych i GPU co bazowy przebieg ~13 min.

## Aktualna ścieżka exact scoring dla jednego chunka

Dla wordlisty mieszczącej się w jednym rezydentnym chunku dokładny gain jest
obliczany z użyciem osobnej, otwartej tablicy hashującej na GPU dla każdej
reguły. Tablice mają pojemność co najmniej dwukrotnie większą od liczby słów.
GPU zwraca do CPU wyłącznie mały wektor liczników unikalnych slotów; pełne listy
trafień pozostają na GPU. Po wybraniu najlepszego kandydata z batcha jego
sloty są kopiowane D2D do bufora zwycięzcy, używanego bez ponownego przejścia
wordlisty przez `apply_winner_and_clear`.

Dla wordlist wielochunkowych pozostaje dotychczasowa ścieżka kompaktowych
wyników i deduplikacji CPU, ponieważ duplikaty mogą występować pomiędzy
chunkami. Ścieżkę GPU można wyłączyć przez `RANKER_EXACT_GPU_DEDUP=0`.

Metryki postępu CELF oddzielają całkowity elapsed od tempa i ETA liczonego od
pierwszego zwycięzcy. Dodatkowo raportowane jest `rescored/s`, czyli tempo
ponownego dokładnego przeliczania kandydatów po pierwszej rundzie.
