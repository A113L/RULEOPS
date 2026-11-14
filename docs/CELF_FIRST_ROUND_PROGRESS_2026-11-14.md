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

## 3. Transfery exact wyników GPU -> CPU

`score_exact_batch_kernel` zapisuje zwarte rekordy `uint32 slot + uint8 rule_id`
we wspólnym buforze. Dla każdego word-chunka host wykonuje jeden odczyt licznika
oraz dwa odczyty zbiorcze (tablica slotów i tablica lokalnych ID reguł), niezależnie
od liczby reguł w batchu. Na CPU rekordy są grupowane według ID reguły, po czym
`np.unique` nadal usuwa duplikaty w obrębie reguły i między word-chunkami.

Dodatkowa pamięć bufora wynikowego wynosi 1 bajt na maksymalny możliwy hit ponad
wcześniejsze sloty `uint32` (25% więcej pamięci dla tych buforów). Zamiast
osobnego kernela pakującego używany jest globalny licznik append w istniejącym
kernelu exact, więc nie dochodzi dodatkowy dispatch. Raport profilowania podaje
liczbę zbiorczych kopii D2H oraz szacowaną liczbę unikniętych kopii per-reguła.

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
