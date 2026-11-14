# CELF: postęp pierwszej rundy i optymalizacja batchy

## 1. Raportowanie pierwszej rundy

`_GpuScorer.score_exact_batch()`, `score_batch()` i `_score_single_recording()`
przyjmują opcjonalny `progress_callback`. Callback aktualizuje pasek i emituje
trwały heartbeat co 8 sekund. Licznik `selected/N` nadal rośnie dopiero po
zatwierdzeniu zwycięzcy; praca wewnątrz rundy jest raportowana osobno.

Pasek CELF ma krótszy opis. Przy wąskim terminalu renderer skraca wizualny
prefiks, ale zachowuje końcowe pola diagnostyczne `gpu_dispatches` i
`rescored`. Po zakończeniu pierwszej rundy loguje czas, indeks zwycięzcy,
liczbę dispatchów GPU i liczbę przeliczonych challengerów.

## 2. Batchowanie i dispatches

- Domyślny `RANKER_GREEDY_RESCORE_BATCH` wynosi teraz 256 (wcześniej 128).
- Domyślny `RANKER_EXACT_BATCH` wynosi teraz 128 (wcześniej 64).
- Oba batch'e są ograniczane przez `rule_batch_size` i
  `MAX_DISPATCH_ITEMS / max_chunk_words`, aby typowo pozostać pojedynczym
  legalnym kernelem na word-chunk.
- `RANKER_EXACT_BATCH` jest dodatkowo ograniczany do 256, bo lokalny identyfikator
  reguły w skompaktowanym strumieniu wyników ma typ `uint8`.
- Grupowanie exact challengerów przegląda ograniczone okno do 4x limitu batcha.
  Nieświeże wpisy kopca są odkładane i przywracane, a świeże challengery mogą
  być dokładnie przeliczane razem, nawet jeśli nie leżą bezpośrednio obok siebie
  w kopcu. Obliczenia nie zmieniają aktywnego zbioru, więc kolejność sprawdzania
  exact gain nie zmienia kryterium zwycięzcy ani tie-breaku.

## 3. Exact scoring: liczniki per reguła, kompakcja GPU i transfer GPU -> CPU

`score_exact_batch_kernel` zapisuje trafienia w osobnych segmentach dla każdej
reguły. Każda reguła ma własny `atomic_add` na swoim liczniku; nie ma jednego
licznika współdzielonego przez cały batch. Pojemność segmentu odpowiada
maksymalnej liczbie słów w chunku, więc reguła nie może zapisać więcej niż
jedno trafienie na pozycję słowa.

Po scoringu host odczytuje mały wektor liczników i buduje prefiksowe offsety.
`compact_exact_hits_kernel` przepisuje tylko faktyczne trafienia do zwartego
bufora, uruchamiając work-item wyłącznie dla liczby trafień. Nie ma macierzy
sentineli ani osobnej tablicy identyfikatorów reguł.

CPU wykonuje jeden zbiorczy odczyt D2H slotów kompaktowanego wyniku dla każdego
niepustego word-chunka. Odczyt małego wektora liczników jest oddzielnym
transferem sterującym; nie przenosi danych slotów. Zwarty strumień jest
rozdzielany na reguły zgodnie z licznikami. Duplikaty pozostają do końcowego
`np.unique` wykonywanego osobno dla każdej reguły przez wszystkie word-chunki.
Dokładny gain, aktywny zbiór, kryterium wyboru i tie-break CELF pozostają
niezmienione.

Profil `exact-result D2H` raportuje odczyty zwartego strumienia, transfer małych
liczników, rozmiary transferów oraz liczbę uruchomień kernela compaction.

## 4. Liczniki GPU

`gpu_dispatches` zlicza teraz rzeczywiste wywołania kernel launch w operacjach
CELF: singleton exact, batch tighten, exact batch oraz zastosowanie zwycięzcy.
Raport profilu podaje łączną liczbę `gpu_kernel_dispatches`. Dzięki temu nowy
pomiar można porównać z wcześniejszymi licznikami, które odzwierciedlały wywołania
metod scoringowych, a nie zawsze rzeczywistą liczbę kernel launchy.

## Weryfikacja

- Pełny `pytest -q`: **565 passed, 5 skipped**.
- Źródło OpenCL wygenerowane przez `get_recompute_kernel_source()` przechodzi
  kontrolę składni `clang -x cl -cl-std=CL1.2 -fsyntax-only`.
- Integracyjny test GPU jest pominięty, ponieważ środowisko testowe nie ma
  runtime OpenCL.
- Nie wykonano benchmarku na RTX 3060 Ti. Nowe wartości batchy i globalny append
  trzeba potwierdzić na tej karcie; testy jednostkowe nie dowodzą przyspieszenia.

## Zalecany pomiar na RTX 3060 Ti

Wykonać ten sam dataset z profilem włączonym i zachować te same `rules-file`,
`wordlist`, `cracked`, `budgets` i parametry CLI. Porównać `gpu_kernel_dispatches`,
czas `fresh_resolve_exact_batch`, `batch_tighten`, `exact-result D2H`, całkowity
czas CELF, VRAM i pokrycie. W razie presji pamięci lub pogorszenia czasu można
ustawić `RANKER_EXACT_BATCH=64` i/lub `RANKER_GREEDY_RESCORE_BATCH=128`.
