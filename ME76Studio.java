// ============================================================================
// ME7.6.2 STUDIO - Opel Astra-H Z20LET (Bosch 0261208153 / 372871)
//
// Jeden skrypt z GUI: wybierasz, co wstrzyknac, a on:
//   - zaklada TABLICE KALIBRACYJNA (CAL) w wolnym flashu,
//   - generuje stuby, ktore progi i maski CZYTAJA Z TABLICY (nie z immediatow),
//   - eksportuje bin i weryfikuje go z dysku,
//   - wypisuje MAPPACK CSV ze wszystkimi wartosciami kalibracyjnymi.
//
// ==================== DLACZEGO TABLICA CAL ====================
// W poprzednich buildach progi byly zaszyte jako immediaty. Asembler C166
// pakuje male stale w SKROCONA forme: "movb RL4,#0x5" to dwa bajty "E1 58",
// gdzie piatka jest NIBBLEM wewnatrz opcode'u. Takiej wartosci nie da sie
// wystawic w mappacku jako edytowalnej - nie ma osobnego bajtu do zmiany.
// Dlatego kazda wartosc kalibracyjna mieszka teraz w tablicy jako pelne slowo,
// a stuby czytaja ja przez r6. Kosztuje to kilka bajtow na prog i jeden
// dodatkowy rejestr na stosie - w zamian caly build da sie stroic w WinOLS.
//
// ==================== BITMAPA ENABLE ====================
// Slowo 0 tablicy wlacza i wylacza moduly W RUNTIME, bez przebudowy:
//   bit 0 (0x01) - launch control
//   bit 1 (0x02) - no-lift shift
//   bit 2 (0x04) - selektor bankow (pedaly)
//   bit 3 (0x08) - multimapa (czyste = wszystkie wskazniki jak bank 0 = seria)
// Wpisanie 0x0000 robi z pliku sterownik zachowujacy sie jak seryjny, mimo
// ze caly kod siedzi we flashu. To jest sciezka wyjscia, jesli cos na torze
// zacznie sie dziwnie zachowywac: jedna wartosc, nie reflash.
//
// ==================== NLS: OCENA NA ZBOCZU ====================
// O tym, czy NLS ma dzialac, decyduja obroty w CHWILI wcisniecia sprzegla -
// raz, nie co wtrysk. Wcisniecie ponizej okna rozbraja NLS na cale to
// wcisniecie, wiec silnik kreci sie swobodnie do odciecia nawet gdy po drodze
// przejdzie przez okno. Poprzednia wersja testowala okno ciagle i dlatego
// robila sciane na dolnej granicy.
//
//@category ME7
// ============================================================================

import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.assembler.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.model.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.util.*;

public class ME76Studio extends GhidraScript {

    static final String PROG_MATCH = "Astra";

    // ---------------- TABLICA CAL ----------------
    // Kolejnosc = indeks slowa. Adres slowa i = CAL_BASE + 2*i, operand 0x7000 + 2*i.
    // kolumny: nazwa | modul | typ | factor | jednostka | domyslna (hex) | opis | flaga
    static final String[][] CAL = {
      {"ENABLE",           "System",       "bitmapa","1",   "bitmapa", "007F",
       "bit0 LC | bit1 NLS | bit2 selektor bankow + lampka MIL | bit3 multimapa | bit4 sufit napelnienia po biegu | bit5 rotacja strategii ciecia | bit6 rolling LC (cancel na dzwigni). 0x0000 = sterownik zachowuje sie jak seryjny","UWAGA"},
      // ---- DRABINKA LC: prog, kat i maska na kazdy stopien ----
      {"LC TH stopien 1",  "ClutchLaunch", "u16",    "0.25","obr/min", "2D50",
       "prog stopnia 1. Ponizej tego progu LC nie robi NIC",""},
      {"LC TH stopien 2",  "ClutchLaunch", "u16",    "0.25","obr/min", "3070",
       "prog stopnia 2",""},
      {"LC TH stopien 3",  "ClutchLaunch", "u16",    "0.25","obr/min", "3390",
       "prog stopnia 3",""},
      {"LC TH stopien 4",  "ClutchLaunch", "u16",    "0.25","obr/min", "36B0",
       "prog stopnia 4 - najwyzszy. To on trzyma sciane przy targecie",""},
      {"LC ZW stopien 1",  "ClutchLaunch", "i8w",    "0.75","st",      "00FC",
       "kat zaplonu w stopniu 1 (bajt ze znakiem, ujemne = po GMP). Siatka 0.75 st/bit","PARA"},
      {"LC ZW stopien 2",  "ClutchLaunch", "i8w",    "0.75","st",      "00F8",
       "kat zaplonu w stopniu 2","PARA"},
      {"LC ZW stopien 3",  "ClutchLaunch", "i8w",    "0.75","st",      "00F3",
       "kat zaplonu w stopniu 3. 10 st nie da sie wpisac - siatka 0.75 daje 9.75 (0xF3) albo 10.5 (0xF2)","PARA"},
      {"LC ZW stopien 4",  "ClutchLaunch", "i8w",    "0.75","st",      "00EC",
       "kat zaplonu w stopniu 4 - najglebszy","PARA"},
      {"LC MASKA A st.1",  "ClutchLaunch", "u8w",    "1",   "bitmapa", "0000",
       "cylindry ciete w stopniu 1, polowka A. 0x00 = sam retard, bez ciecia","MASKA"},
      {"LC MASKA A st.2",  "ClutchLaunch", "u8w",    "1",   "bitmapa", "0001",
       "cylindry ciete w stopniu 2, polowka A (0x01 = cyl 1)","MASKA"},
      {"LC MASKA A st.3",  "ClutchLaunch", "u8w",    "1",   "bitmapa", "0005",
       "cylindry ciete w stopniu 3, polowka A (0x05 = cyl 1+3)","MASKA"},
      {"LC MASKA A st.4",  "ClutchLaunch", "u8w",    "1",   "bitmapa", "0007",
       "cylindry ciete w stopniu 4, polowka A. 0x0F = wszystkie cztery - SILNIK GASNIE","MASKA"},
      {"LC MASKA B st.1",  "ClutchLaunch", "u8w",    "1",   "bitmapa", "0000",
       "polowka B stopnia 1. Rotacja po bicie 2 anzti. A=B znaczy brak rotacji. BITY: 0x01=cyl1 0x02=cyl3 0x04=cyl4 0x08=cyl2 (kolejnosc zaplonu, nie numeracja)","MASKA"},
      {"LC MASKA B st.2",  "ClutchLaunch", "u8w",    "1",   "bitmapa", "0002",
       "polowka B stopnia 2 (0x02 = cyl 3 wg kolejnosci zaplonu). Naprzemiennie z A, zeby nie chlodzic zawsze tego samego cylindra","MASKA"},
      {"LC MASKA B st.3",  "ClutchLaunch", "u8w",    "1",   "bitmapa", "000A",
       "polowka B stopnia 3 (0x0A = cyl 3 + cyl 2)","MASKA"},
      {"LC MASKA B st.4",  "ClutchLaunch", "u8w",    "1",   "bitmapa", "000D",
       "polowka B stopnia 4. Z A=0x07 daje w cyklu trzy rozne cylindry","MASKA"},
      {"LC SPEED_MAX",     "ClutchLaunch", "u8w",    "1",   "raw",     "0005",
       "gorna granica predkosci dla LC. Powyzej tej wartosci sciezka idzie do NLS. SKALOWANIE NIEPOTWIERDZONE - wartosc surowa","UWAGA"},
      {"NLS RPM_MIN",      "NLS",          "u16",    "0.25","obr/min", "4E20",
       "dolna granica okna uzbrojenia. Sprawdzana RAZ, na zboczu wcisniecia sprzegla",""},
      {"NLS RPM_MAX",      "NLS",          "u16",    "0.25","obr/min", "6590",
       "gorna granica okna uzbrojenia. Sprawdzana RAZ, na zboczu wcisniecia sprzegla",""},
      {"NLS DUR",          "NLS",          "u16",    "1",   "wtryskow","00C0",
       "limit dlugosci ciecia we wtryskach. Licznik chodzi tylko gdy realnie tniemy. 192 to ~1,05 s przy 5500 obr",""},
      {"NLS ZW",           "NLS",          "i8w",    "0.75","st",      "00E5",
       "kat zaplonu podczas NLS (bajt ze znakiem)",""},
      {"NLS RL_MIN",       "NLS",          "u8w",    "1",   "raw",     "0050",
       "minimalne obciazenie, przy ktorym NLS tnie. SKALOWANIE NIEPOTWIERDZONE - wartosc surowa","UWAGA"},
      {"NLS MASK",         "NLS",          "u8w",    "1",   "bitmapa", "000F",
       "cylindry z odcietym wtryskiem podczas NLS (0x0F = wszystkie cztery, krotko)","MASKA"},
      {"SEL RPM_IDLE_MAX", "BankSelect",   "u16",    "0.25","obr/min", "1770",
       "gorna granica obrotow uznawanych za bieg jalowy przy wyborze banku",""},
      {"SEL OPCJE",        "BankSelect",   "u8w",    "1",   "bitmapa", "0003",
       "bit0 = wymagaj wcisnietego sprzegla; bit1 = blokuj gdy tempomat reguluje; bit2 = pozwol przelaczac w ruchu (pomija postoj i obroty). 0x03 = sprzeglo + blokada tempomatu","MASKA"},
      {"SEL MIL_ON",       "BankSelect",   "u16",    "1",   "przebiegow","0020",
       "ile przebiegow listy zadan lampka swieci w jednym mrugnieciu. DO ZMIERZENIA NA AUCIE","UWAGA"},
      {"SEL MIL_PER",      "BankSelect",   "u16",    "1",   "przebiegow","0040",
       "swiecenie plus przerwa - okres jednego mrugniecia. Musi byc wieksze od MIL_ON","UWAGA"},
      {"SEL MASKA TIP+",   "BankSelect",   "u8w",    "1",   "bitmapa", "0008",
       "bit w ggfgrhAusBits10ms (0xF0415) dla tipu PRZYSPIESZ = bank w gore. 0x08 = B_fgrtbe, 0x20 = B_fgrtse (SET), 0x10 = trzymany","MASKA"},
      {"SEL MASKA TIP-",   "BankSelect",   "u8w",    "1",   "bitmapa", "0040",
       "bit w ggfgrhAusBits10ms dla tipu ZWOLNIJ = bank w dol. 0x40 = B_fgrtve, 0x80 = trzymany","MASKA"},
      {"RLC TH stopien 1", "RollingLC",    "u16",    "0.25","obr/min", "2EE0",
       "dolna granica okna. Ponizej tego rolling LC NIE tnie - silnik ma ciagnac","",},
      {"RLC TH stopien 2", "RollingLC",    "u16",    "0.25","obr/min", "39D0",""+
       "prog stopnia 2",""},
      {"RLC TH stopien 3", "RollingLC",    "u16",    "0.25","obr/min", "44C0",
       "prog stopnia 3",""},
      {"RLC TH stopien 4", "RollingLC",    "u16",    "0.25","obr/min", "4E20",
       "prog stopnia 4 = GORNA granica okna. Powyzej niego stopien 4 zostaje, wiec obroty stoja tutaj jak na ograniczniku","UWAGA"},
      {"RLC ZW stopien 1", "RollingLC",    "i8w",    "0.75","st",      "00FD",
       "kat zaplonu w stopniu 1 (bajt ze znakiem). Lagodniej niz LC, bo tniemy pod obciazeniem",""},
      {"RLC ZW stopien 2", "RollingLC",    "i8w",    "0.75","st",      "00FA",
       "kat zaplonu w stopniu 2",""},
      {"RLC ZW stopien 3", "RollingLC",    "i8w",    "0.75","st",      "00F6",
       "kat zaplonu w stopniu 3",""},
      {"RLC ZW stopien 4", "RollingLC",    "i8w",    "0.75","st",      "00F0",
       "kat zaplonu w stopniu 4",""},
      {"RLC MASKA A st.1", "RollingLC",    "u8w",    "1",   "bitmapa", "0000",
       "cylindry ciete w stopniu 1, polowka A. 0x00 = sam retard. BITY: 0x01=cyl1 0x02=cyl3 0x04=cyl4 0x08=cyl2","MASKA"},
      {"RLC MASKA A st.2", "RollingLC",    "u8w",    "1",   "bitmapa", "0000",
       "polowka A stopnia 2","MASKA"},
      {"RLC MASKA A st.3", "RollingLC",    "u8w",    "1",   "bitmapa", "0001",
       "polowka A stopnia 3","MASKA"},
      {"RLC MASKA A st.4", "RollingLC",    "u8w",    "1",   "bitmapa", "0005",
       "polowka A stopnia 4","MASKA"},
      {"RLC MASKA B st.1", "RollingLC",    "u8w",    "1",   "bitmapa", "0000",
       "polowka B stopnia 1. Rotacja po bicie 2 anzti, zeby nie chlodzic zawsze tego samego cylindra","MASKA"},
      {"RLC MASKA B st.2", "RollingLC",    "u8w",    "1",   "bitmapa", "0000",
       "polowka B stopnia 2","MASKA"},
      {"RLC MASKA B st.3", "RollingLC",    "u8w",    "1",   "bitmapa", "0002",
       "polowka B stopnia 3","MASKA"},
      {"RLC MASKA B st.4", "RollingLC",    "u8w",    "1",   "bitmapa", "000A",
       "polowka B stopnia 4","MASKA"},
      {"RLC SPEED_MIN",    "RollingLC",    "u8w",    "1",   "raw",     "0005",
       "minimalna predkosc. Ponizej niej rolling LC nie ruszy, zeby nie dalo sie tego odpalic na postoju ani na luzie. SKALOWANIE NIEPOTWIERDZONE","UWAGA"},
      {"RLC MASKA BTN",    "RollingLC",    "u8w",    "1",   "bitmapa", "0001",
       "bit przycisku w ggfgrhAusBits10ms (0xF0415). 0x01 = B_fgrat, czyli CANCEL na dzwigni tempomatu","MASKA"},
      {"STRAT SPARK ALL",  "Strategia",    "u8w",    "1",   "bitmapa", "000F",
       "maska cylindrow dla strategii 3 (hard spark cut). 0x0F = wszystkie cztery. To sa juz bity ZAPLONU, nie paliwa - nie przepuszczam ich przez odwracanie","MASKA"},
    };
    // ================= ZNAK WODNY =================
    // Unikalny marker per KOPIA pliku. To sa czyste DANE, nie kod - nic nie
    // wykonuje, wiec nie zmienia zachowania sterownika. Lezy w zakresie sumy 33
    // (chip 0x0B4000..0x0B7EFF), wiec nie da sie go wymazac bez zerwania sumy.
    // NIE jest to zabezpieczenie przed odczytem - kazdy z BDM przeczyta plik.
    // Sluzy do jednego: udowodnienia, ktora to kopia i komu wydana.
    //
    // >>> USTAW TO PRZED KAZDYM WYDANIEM PLIKU <<<
    static final String WM_OWNER  = "KUBA";        // wlasciciel / autor patcha (do 16 znakow ASCII)
    static final String WM_TARGET = "";            // komu wydane (klient), do 20 znakow. Puste = kopia wlasna
    static final int    WM_SERIAL = 0x00000001;    // numer kolejny kopii - PODNOS przy kazdym wydaniu
    static final long   WM_BASE   = 0x0B7080L;     // chip; plik 0x0A7080, 64 B, w zakresie sumy 33
    static final byte[] WM_MAGIC  = {'M','E','7','6','W','M'};
    static final int    WM_VER    = 0x01;

    static final long CAL_BASE = 0x0B7000L;
    static final int  CAL_N    = CAL.length;
    // Slowo wersji SCHEMATU tablicy, zaraz za tablica. Gdy zmienia sie UKLAD
    // tablicy (a nie tylko wartosci), stare bajty znaczylyby co innego pod nowymi
    // nazwami. Niezgodna wersja wymusza przesiew i mowi o tym wprost, zamiast
    // po cichu zostawic liczby, ktore juz nie pasuja do kodu.
    static final long CAL_VER_A = CAL_BASE + 2L*CAL.length;
    static final int  CAL_VER   = 0x0005;
    // indeksy
    static final int C_EN=0;
    static final int C_TH=1;      // TH stopien 1..4  -> indeksy 1,2,3,4
    static final int C_ZW=5;      // ZW stopien 1..4  -> indeksy 5,6,7,8
    static final int C_MA=9;      // MASKA A st.1..4  -> indeksy 9,10,11,12
    static final int C_MB=13;     // MASKA B st.1..4  -> indeksy 13,14,15,16
    static final int C_SPD=17, C_NMIN=18, C_NMAX=19, C_NDUR=20, C_NZW=21,
                     C_NRL=22, C_NMK=23, C_IDLE=24, C_SOPT=25,
                     C_MON=26, C_MPER=27, C_MUP=28, C_MDN=29;
    // rolling LC: wlasny komplet progow, katow i masek
    static final int C_RTH=30, C_RZW=34, C_RMA=38, C_RMB=42,
                     C_RSPD=46, C_RBTN=47, C_AZALL=48;

    /** operand 16-bit slowa CAL nr i (okno DPP1) */
    static String cw(int i) {
        long a = CAL_BASE + 2L*i;
        return "0x" + Long.toHexString((a & 0x3FFFL) | 0x4000L);
    }
    static long calAddr(int i) { return CAL_BASE + 2L*i; }

    // ---------------- zmienne w XRAM ----------------
    // V_HOLD i V_ARMED zostaly po starym przelaczaniu hamulcem - dzis nieuzywane,
    // ale adresy zostawiam zajete, zeby przyszla zmienna tam nie wladowala sie
    // na smieci po poprzednim buildzie w tym samym XRAM.
    static final String V_HOLD="0xaf20", V_BANK="0xaf22", V_ARMED="0xaf23",
                        V_PREVB="0xaf24", V_BLPH="0xaf25", V_BLTM="0xaf26",
                        V_NLSC="0xaf28", V_PREVK="0xaf2a", V_LCSTG="0xaf2b",
                        V_MILON="0xaf2c", V_STRAT="0xaf2d", V_AZMSK="0xaf2e",
                        V_RSTG="0xaf2f";

    // gangi - aktualny bieg, 0xF03BF (A2L: "Ist-Gang"), okno DPP2.
    // 0 = bieg nierozpoznany, 1..6 = biegi, 7 = wsteczny. Liczony z ilorazu n/v,
    // wiec ponizej NGANGMIN (1400 obr/min) jest po prostu 0 - i tak ma byc
    // traktowany: jako "nie wiem", a nie jako "ostatni znany".
    static final String GANGI="0x83bf";
    // azoffmsk_w - maska wygaszania wyjscia zaplonu, 0xF8AE. Stopien wyjsciowy
    // robi dla kazdego cylindra:  movb RL2,[r3+0x679E] ; and r2,azoffmsk_w ;
    // jmpa cc_NE,<pomin zaplon>. Tablica pod 0x0B679E to 08 04 02 01, czyli
    // BIT NA CYLINDER - potwierdzone, nie zgadywane.
    static final String AZOFF="0xf8ae";

    // Dzwignia tempomatu i sprzeglo - adresy wprost z A2L, okno DPP2 (strona 0x3C).
    //   ggfgrhAusBits10ms  0xF0415 -> operand 0x8415   bity dzwigni, odswiezane co 10 ms
    //     0x01 B_fgrat wylacz | 0x02 B_fgrhev blad | 0x04 B_fgrhsa wylacznik glowny OFF
    //     0x08 B_fgrtbe PRZYSPIESZ | 0x10 trzymany | 0x20 B_fgrtse SET
    //     0x40 B_fgrtve ZWOLNIJ    | 0x80 trzymany
    //   fgrreglausbits     0xF0413 -> operand 0x8413   bit0 = B_fgren, tempomat reguluje
    // Oba bajty sa w oryginale czytane instrukcja movbz, wiec adresy sa pewne.
    static final String FGRBTN="0x8415", FGRREG="0x8413";

    static final String NMOT_W="0xf742", VFZG_B="0x80b1", RL_B="0xf837", ANZTI="0xf7c8";
    static final String KUPPL_R="0xfd74"; static final int KUPPL_B=0x3;
    // hamulec - juz nieuzywany przez selektor (przelaczanie poszlo na dzwignie
    // tempomatu), zostawiony na wypadek powrotu do starej metody
    static final String BREMS_R="0xfd72"; static final int BREMS_B=0x3;
    static final String[] ZWOUT={"0x8662","0x8663","0x8664","0x8665"};
    static final String MDL="0xfe0c", MDH="0xfe0e";

    // ---------------- haki ----------------
    static final long H_ANG=0x023F46L;  static final int[] O_ANG={0xDA,0x0C,0xBA,0x66};
    static final long ORIG_ANG=0x0C66BAL;
    static final long H_SEL=0x023F52L;  static final int[] O_SEL={0xDA,0x04,0xFA,0x90};
    static final long ORIG_SEL=0x0490FAL;
    static final long[] H_TI={0x027C60L,0x027CE4L,0x027D68L,0x027DECL};
    static final String[] TI_VAR={"0xf7fa","0xf7fc","0xf7fe","0xf800"};
    static final String[] TI_CYL={"cyl 1","cyl 3","cyl 4","cyl 2"};
    static final int[][] O_TI={{0xF2,0xF1,0xFA,0xF7},{0xF2,0xF1,0xFC,0xF7},
                              {0xF2,0xF1,0xFE,0xF7},{0xF2,0xF1,0x00,0xF8}};
    static final long H_ZW=0x0C6BAEL;   static final int[] O_ZW={0xE6,0xFC,0x3C,0x1C};
    static final long H_LB=0x0713B8L;   static final int[] O_LB={0xE6,0xFD,0x2E,0x00};
    static final long H_PL=0x07CC00L;   static final int[] O_PL={0xF6,0xF4,0x70,0xF8};
    // KFRLSNT - sufit napelnienia dla maks. momentu, 16 obrotow x 8 temperatur otoczenia.
    // Kod laduje wskaznik DANYCH osobno od osi, wiec na bank wystarczy podmienic
    // te jedna instrukcje, a kopia to same dane (256 B). Osie zostaja wspolne.
    static final long H_RS=0x07CD0EL;   static final int[] O_RS={0xE6,0xF4,0x04,0x1D};
    // Lampka MIL. W tym miejscu seryjny kod wlasnie zdecydowal o B_mil (0xFD2A.7):
    //   ...  60 52        and  r5,r2
    //        2D 02        jmpr cc_NE,+2
    //        7F 15        bset 0xFD2A.7      <- lampka ON
    //        0D 01        jmpr +1
    //        7E 15        bclr 0xFD2A.7      <- lampka OFF
    //   ->   F3 F8 E9 91  movb RL4,0x91E9    <- TU wchodzimy, obie galezie tu spadaja
    // Stad B_mil idzie do milstatus (0xF0104: 0=off, 1/3=on, 2=mruga) i dalej po CAN
    // na zegary. Hak tylko DOKLADA nasze zapalenie - nigdy nie gasi tego, co zapalil
    // seryjny kod, wiec realny blad zawsze ma pierwszenstwo nad sygnalizacja banku.
    static final long H_MIL=0x04BB4AL;  static final int[] O_MIL={0xF3,0xF8,0xE9,0x91};
    // Maska zaplonu. Seryjny kod sklada azoffmsk_w tak:
    //   0c5488  mov 0xf8ae,r4          (azfdoff==0x9A -> 0x00FF)
    //   0c548e  mov 0xf8ae,0xff1c      (inaczej 0)
    //   0c5492  jnb 0xfda8.2,0x0c549e
    //   0c5496  movbz r4,0x8659
    //   0c549a  or  0xf8ae,r4          (dolozenie z innego zrodla)
    //   0c549e  bmov 0xfda8.3,0xfd34.8 <- TU, zejscie obu galezi, rowno 4 bajty
    // Wchodzimy w punkt zejscia, wiec mamy ostatnie slowo, a przy tym tylko
    // DOKLADAMY bity operacja OR - nie kasujemy zadnego zadania sterownika.
    static final long H_AZ=0x0C549EL;   static final int[] O_AZ={0x4A,0x1A,0x54,0x83};

    // ---------------- stuby: bazy PRZYDZIELANE W RUNTIME (rozproszenie) ----------------
    // Bazy nie sa juz stalymi adresami. Alokator layoutPatch() rozrzuca stuby po
    // trzech oknach (tych samych co decoye), przeplatajac realny kod z falszywym,
    // wiec zaden pojedynczy region diffa nie jest "calym patchem". Dummy adres na
    // start jest wazny tylko po to, by pierwszy przebieg pomiaru rozmiarow mial co
    // wstawic w 'calls' (calls ma 4 B niezaleznie od celu).
    long S_ANG=0x0CC000L, S_CM=0x0CC000L;
    long[] S_C={0x0CC000L,0x0CC000L,0x0CC000L,0x0CC000L};
    long S_SEL=0x0CC000L, S_ZWP=0x0CC000L, S_LBP=0x0CC000L,
         S_RSP=0x0CC000L, S_MIL=0x0CC000L, S_AZ=0x0CC000L,
         S_RLC=0x0CC000L, S_ROU=0x0CC000L;
    // stary CONTIGUOUS blok stubow (dawny uklad) - do wyczyszczenia na fresh/REV
    static final long OLD_LO=0x0CBA00L, OLD_HI=0x0CBE40L;
    static final long S_OLD_LO=0x0CC000L, S_OLD_HI=0x0CC800L;

    // ---------------- OKNA + WSPOLNY ALOKATOR ----------------
    // Trzy wolne okna 0xFF w trzech roznych rekordach sumy. Alokator wydaje z nich
    // regiony ZAROWNO stubom, jak i decoyom - wiec realne i falszywe bloki lezA
    // przeplecione w tych samych oknach i nie da sie po polozeniu zgadnac ktory
    // jest ktory. Even-align (instrukcje C166 na parzystych), fit + isFF pilnowane.
    static final long[][] WIN = {
        {0x0CC000L, 0x0CFF00L},   // W_A rec39, ~15 kB (reklamacja starego bloku stubow)
        {0x0BF720L, 0x0BFA40L},   // W_B rec35, ~800 B (nad kopiami KFRLSNT po biegu)
        {0x01FE40L, 0x01FFA0L},   // W_C rec3,  ~350 B (za watermarkiem 3)
    };
    long[] WINCUR=null;
    void allocInit(){ WINCUR=new long[]{WIN[0][0],WIN[1][0],WIN[2][0]}; }
    long alloc(int w,int size) throws Exception {
        long base=WINCUR[w];
        if(base+size>WIN[w][1]) throw new Exception("alloc: okno "+w+" pelne ("+size+" B)");
        if(!isFF(base,base+size)) throw new Exception("alloc: nie 0xFF @0x"+Long.toHexString(base)+" (okno "+w+")");
        long nx=base+size; if((nx&1)!=0) nx++; WINCUR[w]=nx; return base;
    }
    // przydziel gdzie sie miesci, zaczynajac od preferowanego okna (round-robin)
    long allocFit(int pref,int size) throws Exception {
        for(int k=0;k<WIN.length;k++){ int w=(pref+k)%WIN.length;
            if(WINCUR[w]+size<=WIN[w][1] && isFF(WINCUR[w],WINCUR[w]+size)) return alloc(w,size); }
        throw new Exception("allocFit: brak miejsca na "+size+" B w zadnym oknie");
    }
    void wipeWindows() throws Exception {
        for(long[] w:WIN){ byte[] ff=new byte[(int)(w[1]-w[0])]; Arrays.fill(ff,(byte)0xFF); wr(w[0],ff); }
    }

    // ---------------- FALSZYWY KOD (decoy) + redundantne watermarki ----------------
    // Bloki wygladajace jak logika tuningu (czytaja NMOT/predkosc/dzwignie, robia
    // drabinki porownan, skladaja maski), ale NIC ich nie wola z zywego kodu, wiec
    // nigdy sie nie wykonuja -> zero ryzyka cegly. Sa spiete w PIERSCIEN calls-ami
    // (decoy i -> decoy i+1 -> ... -> decoy 0), zeby narzedzie RE widzialo, ze
    // "cos je wola" i nie odrzucilo ich odruchowo jako martwych. Przydzielane z tego
    // samego alokatora co stuby -> przeplecione z realnym kodem. Deterministyczne
    // (staly seed), wiec SHA pliku nie skacze miedzy buildami.
    // UCZCIWIE: to podnosi KOSZT skopiowania (trzeba przeanalizowac kazdy blok,
    // zeby odkryc ktory jest prawdziwy), a nie daje matematycznej niemozliwosci.
    // Zapisy z decoy ida do martwego XRAM (0xaf50+), ktorego nic nie czyta.
    static final long D_SEED = 0x4D45373662616974L;   // "ME76bait"
    static final int  DEC_N  = 6;
    // drugi i trzeci watermark - te same 64 B co glowny, w innych rekordach sumy,
    // zeby wymazanie jednego nie skasowalo dowodu autorstwa. Poza zakresami WIN.
    static final long WM_BASE2 = 0x0BFA80L;   // rec35, pod tablica sum (0xBFB80)
    static final long WM_BASE3 = 0x01FE00L;   // rec3

    // ---------------- multimapa ----------------
    static final long T_ZW=0x0B6C70L, T_LBOFF=0x0B6C78L, T_LBPG=0x0B6C80L, T_BOOST=0x0B6C84L;
    static final String O_ZWT="0x6c70", O_LBOFFT="0x6c78", O_LBPGT="0x6c80", O_BOOSTT="0x6c84";
    static final long MAP_ZW=0x0B1C3CL; static final int SZ_ZW=192;
    static final long MAP_LB=0x0B8E18L; static final int SZ_LB=192;
    static final long ZW_B1=0x0B6D00L, ZW_B2=0x0B6DC0L, LB_B1=0x0B6E80L, LB_B2=0x0B6F40L;
    static final long HOLE_LO=0x0B6C70L, HOLE_HI=0x0B7000L;
    // KFRLSNT: tabela offsetow danych na bank (strona 0x2F, wiec strona sie nie zmienia)
    static final long T_RS=0x0B6C8CL;   static final String O_RST="0x6c8c";
    // Sufit napelnienia po BIEGU: 6 kopii danych KFRLSNT + tablica wskaznikow.
    // Kopie MUSZA lezec na tej samej stronie co oryginal (0x0BC000..0x0BFFFF),
    // bo w tablicy siedza 14-bitowe offsety w stronie, a nie pelne adresy.
    // Wolny obszar 0xFF zaczyna sie na 0x0BF040 i ciagnie do tablicy sum
    // pod 0x0BFB80, wiec 6 x 256 B miesci sie z zapasem.
    static final long T_GEAR=0x0B6C94L; static final String O_GEART="0x6c94";
    static final long RG_BASE=0x0BF100L; static final int RG_N=6;
    // Odwracanie nibbla maski. Nasze bity ti ida 0x01,0x02,0x04,0x08 w kolejnosci
    // zaplonu; tablica zaplonu pod 0x0B679E ma 08,04,02,01 - czyli ODWROTNIE.
    // Bez tego selective spark ciolby iskre na innych cylindrach niz paliwo.
    static final long T_REV=0x0B6CA0L;  static final String O_REVT="0x6ca0";
    static final long RS_SRC=0x0BDD04L;             // dane seryjne
    static final long RS_B1=0x0BEE40L, RS_B2=0x0BEF40L;
    static final int  SZ_RS=256;                    // 16 x 8 x u16
    static final int  RS_OFF0=(int)(RS_SRC & 0x3FFF);
    static final long AZYTIAB=0x0B05B8L;

    Program prog; AddressSpace sp; Memory mem; Assembler asm;
    long fbase=0x010000L;
    List<String> plist=new ArrayList<String>();
    // Tryb wydania klientowi: serial rozwiazywany w RUNTIME (auto-inkrement z pliku
    // licznika), nie ze stalej. Poza trybem klienta uzywamy stalej WM_SERIAL.
    boolean clientMode=false;
    int     wmSerial=WM_SERIAL;
    // Auto-inkrement serialu z pliku licznika obok pliku wyjsciowego. Kazdy build
    // klienta dostaje unikalny numer bez recznego podnoszenia WM_SERIAL.
    int nextClientSerial(File dir){
        File f=new File(dir,"me76_serial.txt");
        int s=WM_SERIAL;
        try{ if(f.exists()){ String t=new String(java.nio.file.Files.readAllBytes(f.toPath()),"US-ASCII").trim();
            if(!t.isEmpty()) s=Integer.parseInt(t); } }catch(Exception e){}
        try{ java.io.FileWriter w=new java.io.FileWriter(f); w.write(Integer.toString(s+1)); w.close(); }catch(Exception e){}
        return s;
    }

    Address at(long a){ return sp.getAddress(a); }
    static String callsHex(long a){ return String.format("DA %02X %02X %02X",
        (int)((a>>16)&0xFF),(int)(a&0xFF),(int)((a>>8)&0xFF)); }
    static int ptr16(long a){ return (int)((a&0x3FFFL)|(((a>>14)==0x2D)?0x4000:0)); }

    byte[] rd(long a,int n) throws Exception {
        byte[] b=new byte[n]; for(int i=0;i<n;i++) b[i]=mem.getByte(at(a+i)); return b; }
    String hx(byte[] b){ StringBuilder s=new StringBuilder();
        for(byte x:b) s.append(String.format("%02X ",x&0xFF)); return s.toString().trim(); }
    void wr(long a,byte[] b) throws Exception {
        byte[] bef=rd(a,b.length);
        prog.getListing().clearCodeUnits(at(a),at(a+b.length-1),false);
        mem.setBytes(at(a),b);
        plist.add(String.format("0x%06X | %d B | %s -> %s",a-fbase,b.length,
            hx(bef).length()>48?hx(bef).substring(0,48)+"...":hx(bef),
            hx(b).length()>48?hx(b).substring(0,48)+"...":hx(b))); }
    void dis(long a){ new DisassembleCommand(at(a),null,true).applyTo(prog,monitor); }
    boolean isFF(long lo,long hi) throws Exception {
        for(long a=lo;a<hi;a++) if((mem.getByte(at(a))&0xFF)!=0xFF) return false; return true; }
    boolean br(String l){ String s=l.trim().toLowerCase();
        return s.startsWith("jnb ")||s.startsWith("jb ")||s.startsWith("jmpr "); }
    int brLen(String l){ return l.trim().toLowerCase().startsWith("jmpr ")?2:4; }

    byte[] asmb(long base,String[] lines) throws Exception {
        Map<String,Long> lab=new HashMap<String,Long>();
        long pc=base;
        for(String raw:lines){ String l=raw.trim(); if(l.isEmpty()) continue;
            if(l.endsWith(":")){ lab.put(l.substring(0,l.length()-1),Long.valueOf(pc)); continue; }
            if(br(l)){ pc+=brLen(l); continue; }
            pc+=asm.assembleLine(at(base),l).length; }
        java.io.ByteArrayOutputStream out=new java.io.ByteArrayOutputStream();
        pc=base;
        for(String raw:lines){ String l=raw.trim(); if(l.isEmpty()||l.endsWith(":")) continue;
            String t=l; int i=l.indexOf('@');
            if(i>=0){ Long g=lab.get(l.substring(i+1).trim());
                if(g==null) throw new Exception("Nieznana etykieta: "+l);
                t=l.substring(0,i)+"0x"+Long.toHexString(g.longValue()); }
            byte[] b=asm.assembleLine(at(pc),t);
            if(br(l)&&b.length!=brLen(l)) throw new Exception("Zla dlugosc skoku: "+l+" ("+b.length+")");
            out.write(b); pc+=b.length; }
        return out.toByteArray();
    }

    // ===== ZAMAZANIE (obfuskacja) stubow =====
    // Wstawia miedzy instrukcje blok: 'jmpr cc_UC,@OBFn' + kilka smieciowych
    // instrukcji + 'OBFn:'. Skok bezwarunkowy ZAWSZE przeskakuje smiecie, wiec one
    // NIGDY sie nie wykonuja -> zero zmiany zachowania (dowodliwie: jmpr nie rusza
    // flag ani rejestrow, a martwych bajtow CPU nie wykonuje). Efekt: linearny
    // deasembler i czlowiek czytajacy z gory na dol grzezna w wygladajacym-jak-kod
    // smietniku, a realne instrukcje sa poprzeplatane wstawkami. Smiecie pisza tylko
    // do martwego XRAM 0xaf5a+. Deterministyczne (seed z tagu), wiec faza pomiaru i
    // faza finalna daja identyczny rozmiar. Adaptacyjne: jesli wstawka wypchnie ktorys
    // skok poza zasieg (asmb rzuca), asmbObf zmniejsza liczbe wstawek - build sie uda.
    static final int OBF_MAX = 3;
    static final String[] OBF_RD = {"0xf742","0x80b1","0xf837","0xf7c8"};
    long tagSeed(String tag){ long s=0x9E3779B97F4A7C15L;
        for(int i=0;i<tag.length();i++) s=s*131+tag.charAt(i); return s; }
    String junkLine(java.util.Random rng){
        switch(rng.nextInt(6)){
            case 0:  return "mov r6,#0x"+Integer.toHexString(0x1000+rng.nextInt(0x6000));
            case 1:  return "movb RL5,"+OBF_RD[rng.nextInt(OBF_RD.length)];
            case 2:  return "add r6,r5";
            case 3:  return "shl r6,#0x1";
            case 4:  return "mov 0xaf5a,r6";     // martwy XRAM (nic nie czyta)
            default: return "movb 0xaf5c,RL5";   // martwy XRAM
        }
    }
    List<String> obfuscate(List<String> src, String tag, int level){
        if(level<=0) return src;
        List<Integer> cand=new ArrayList<Integer>();
        for(int i=1;i<src.size();i++){ String l=src.get(i).trim();
            if(l.isEmpty()||l.endsWith(":")||br(l)||l.equalsIgnoreCase("rets")) continue;
            cand.add(Integer.valueOf(i)); }
        if(cand.isEmpty()) return src;
        java.util.Random rng=new java.util.Random(tagSeed(tag));
        int want=Math.min(level,cand.size());
        java.util.TreeSet<Integer> pos=new java.util.TreeSet<Integer>();
        for(int k=0;k<want;k++) pos.add(cand.get((int)((long)(k+1)*cand.size()/(want+1))));
        List<String> out=new ArrayList<String>(); int n=0;
        for(int i=0;i<src.size();i++){ out.add(src.get(i));
            if(pos.contains(Integer.valueOf(i))){
                String lbl=tag+"O"+(n++);
                out.add("jmpr cc_UC,@"+lbl);
                int j=2+rng.nextInt(2);
                for(int q=0;q<j;q++) out.add(junkLine(rng));
                out.add(lbl+":");
            } }
        return out;
    }
    // Asembluj z obfuskacja; przy skoku poza zasieg zmniejsz poziom. Ostatecznie
    // (level 0) asembluj bez obfuskacji - zawsze sukces, poprawnosc zachowana.
    byte[] asmbObf(long base, List<String> src, String tag) throws Exception {
        for(int lvl=OBF_MAX; lvl>0; lvl--){
            try{ return asmb(base, obfuscate(src,tag,lvl).toArray(new String[0])); }
            catch(Exception e){ /* najpewniej skok poza zasieg - probuj mniej wstawek */ }
        }
        return asmb(base, src.toArray(new String[0]));
    }

    void dump(long lo,long hi) throws Exception {
        Listing L=prog.getListing(); Address a=at(lo);
        while(a.getOffset()<hi){ Instruction in=L.getInstructionAt(a);
            if(in==null){ a=a.add(1); continue; }
            println(String.format("   %s  %-14s %s",in.getAddress(),
                hx(rd(in.getAddress().getOffset(),in.getLength())),in));
            a=a.add(in.getLength()); } }

    void collect(DomainFolder f,List<DomainFile> o){
        for(DomainFile d:f.getFiles())
            if(d.getName().toLowerCase().contains(PROG_MATCH.toLowerCase())) o.add(d);
        for(DomainFolder s:f.getFolders()) collect(s,o); }

    MemoryBlock fblk(){ MemoryBlock b2=null;
        for(MemoryBlock b:mem.getBlocks()){ if(!b.isInitialized()||b.getSize()<0x40000) continue;
            if(b2==null||b.getSize()>b2.getSize()) b2=b; } return b2; }

    // ======================= MAIN =======================
    @Override
    public void run() throws Exception {
        // ---------- GUI ----------
        String M_LC  ="Launch control (LC)",
               M_NLS ="No-lift shift (NLS)",
               M_MM  ="Multimapa - 3 banki KFZW/KFLBTS/KFRLSNT",
               M_SEL ="Selektor: sprzeglo+tip = bank, hamulec+tip = strategia, lampka MIL",
               M_GEAR="Sufit napelnienia po BIEGU (boost by gear, 6 tablic)",
               M_STR ="Rotacja strategii ciecia (paliwo / iskra wybrane / iskra wszystkie)",
               M_RLC ="Rolling LC (CANCEL na dzwigni, okno obrotow, w ruchu)",
               M_WM  ="Znak wodny (marker wlasnosci per kopia)",
               M_CSV ="Mappack CSV",
               M_CLIENT="WYDANIE KLIENTOWI (tylko bin+suma, bez A2L/mappacka, serial auto)",
               M_REV ="PRZYWROCENIE seryjnego (usun patch)";
        // Tryb headless/automat: gdy podane argumenty (indeksy 0..10), bierzemy je
        // zamiast okna wyboru. Kolejnosc: 0=LC 1=NLS 2=MM 3=SEL 4=GEAR 5=STR 6=RLC
        // 7=WM 8=CSV 9=CLIENT 10=REV. Bez argumentow - normalne GUI.
        List<String> all=Arrays.asList(M_LC,M_NLS,M_MM,M_SEL,M_GEAR,M_STR,M_RLC,M_WM,M_CSV,M_CLIENT,M_REV);
        List<String> pick;
        String[] aa=getScriptArgs();
        if(aa!=null && aa.length>0){
            pick=new ArrayList<String>();
            for(String s:aa){ int ix=-1; try{ ix=Integer.parseInt(s.trim()); }catch(Exception e){}
                if(ix>=0 && ix<all.size() && !pick.contains(all.get(ix))) pick.add(all.get(ix)); }
            println("[HEADLESS] wybor z argumentow: "+pick);
        } else {
            pick = askChoices("ME7.6.2 Studio",
                "Co wstrzyknac do pliku? (Ctrl = wielokrotny wybor)", all);
        }
        boolean doLC=pick.contains(M_LC), doNLS=pick.contains(M_NLS),
                doMM=pick.contains(M_MM), doSEL=pick.contains(M_SEL),
                doGEAR=pick.contains(M_GEAR), doSTR=pick.contains(M_STR),
                doRLC=pick.contains(M_RLC), doWM=pick.contains(M_WM),
                doCSV=pick.contains(M_CSV), doREV=pick.contains(M_REV);
        clientMode=pick.contains(M_CLIENT);
        // Tryb klienta: wymus watermark ON (dowod autorstwa per kopia) i mappack OFF
        // (mappack + A2L to najwiekszy przeciek IP - klient dostaje sam bin + sume).
        if(clientMode){ doWM=true; doCSV=false;
            println("=== TRYB WYDANIA KLIENTOWI ===");
            println("   watermark WYMUSZONY on, mappack WYMUSZONY off.");
            println("   klientowi wydajemy TYLKO plik .bin (z poprawiona suma) - bez A2L,");
            println("   bez mappacka, bez zrodla. Serial z auto-licznika me76_serial.txt."); }
        // Rotacja strategii potrzebuje selektora, bo to on czyta hamulec i tipy.
        // Bez niego strategia zostalaby na stale na 1 i nie dalabys jej zmienic.
        if(doSTR && !doSEL){
            println("UWAGA: strategie ciecia wymagaja selektora (to on czyta hamulec i tipy).");
            println("       Dowlaczam selektor sam z siebie."); doSEL=true; }
        if(pick.isEmpty()){ println("Nic nie wybrano - koniec."); return; }
        // VIN jest WYLACZNIE etykieta w ostatniej kolumnie mappacku - zadna linijka
        // kodu go nie czyta i nie ma tu zadnego VIN locka. Na czas testow nie pytam.
        // Zeby podpisac mappack, wpisz VIN ponizej zamiast pustego stringa.
        String vin = "";

        // ---------- program ----------
        List<DomainFile> c=new ArrayList<DomainFile>();
        collect(getProjectRootFolder(),c);
        DomainFile best=null; int bn=-1;
        for(DomainFile d:c){ Program p=null;
            try{ p=(Program)d.getDomainObject(this,false,false,monitor);
                 int n=p.getFunctionManager().getFunctionCount(); if(n>bn){bn=n;best=d;} }
            catch(Exception e){} finally{ if(p!=null) p.release(this); } }
        if(best==null){ println("STOP: nie znalazlem programu pasujacego do '"+PROG_MATCH+"'."); return; }

        prog=(Program)best.getDomainObject(this,true,false,monitor);
        int txn=prog.startTransaction("ME7.6.2 Studio");
        boolean ok=false;
        File binOut=null;
        try{
            sp=prog.getAddressFactory().getDefaultAddressSpace();
            mem=prog.getMemory(); asm=Assemblers.getAssembler(prog);
            MemoryBlock fb=fblk(); fbase=fb.getStart().getOffset();

            println("############################################################");
            println("# ME7.6.2 STUDIO");
            println("# plik : "+best.getPathname());
            println("# blok : "+fb.getStart()+" - "+fb.getEnd()
                    +"   (offset w pliku = adres - 0x"+Long.toHexString(fbase)+")");
            println("# wybor: "+pick);
            println("############################################################");

            // ================= PRZYWRACANIE =================
            if(doREV){
                println("");
                println("=== PRZYWRACANIE SERYJNEGO ===");
                wr(H_ANG,tob(O_ANG)); wr(H_SEL,tob(O_SEL));
                for(int k=0;k<4;k++) wr(H_TI[k],tob(O_TI[k]));
                wr(H_ZW,tob(O_ZW)); wr(H_LB,tob(O_LB)); wr(H_PL,tob(O_PL)); wr(H_RS,tob(O_RS));
                wr(H_MIL,tob(O_MIL)); wr(H_AZ,tob(O_AZ));
                byte[] ffr=new byte[SZ_RS]; Arrays.fill(ffr,(byte)0xFF);
                wr(RS_B1,ffr); wr(RS_B2,ffr);
                byte[] fft=new byte[6]; Arrays.fill(fft,(byte)0xFF); wr(T_RS,fft);
                byte[] ffg=new byte[RG_N*SZ_RS]; Arrays.fill(ffg,(byte)0xFF); wr(RG_BASE,ffg);
                byte[] ffgt=new byte[2*RG_N]; Arrays.fill(ffgt,(byte)0xFF); wr(T_GEAR,ffgt);
                byte[] ffrv=new byte[16]; Arrays.fill(ffrv,(byte)0xFF); wr(T_REV,ffrv);
                byte[] ff1=new byte[(int)(OLD_HI-OLD_LO)]; Arrays.fill(ff1,(byte)0xFF); wr(OLD_LO,ff1);
                byte[] ffold=new byte[(int)(S_OLD_HI-S_OLD_LO)]; Arrays.fill(ffold,(byte)0xFF); wr(S_OLD_LO,ffold);
                byte[] ff3=new byte[(int)(HOLE_HI-HOLE_LO)];Arrays.fill(ff3,(byte)0xFF); wr(HOLE_LO,ff3);
                byte[] ff4=new byte[(int)(CAL_VER_A+2-CAL_BASE)]; Arrays.fill(ff4,(byte)0xFF); wr(CAL_BASE,ff4);
                byte[] ffwm=new byte[64]; Arrays.fill(ffwm,(byte)0xFF);
                wr(WM_BASE,ffwm); wr(WM_BASE2,ffwm); wr(WM_BASE3,ffwm);
                // wyzeruj wszystkie trzy okna (stuby rozproszone + decoye) do 0xFF
                wipeWindows();
                for(long h:new long[]{H_ANG,H_SEL,H_ZW,H_LB,H_PL,H_MIL,H_AZ}) dis(h);
                for(int k=0;k<4;k++) dis(H_TI[k]);
                println("   wszystkie haki przywrocone, obszary patcha wyzerowane do 0xFF");
                println("   UWAGA: azytiab @0x"+Long.toHexString(AZYTIAB)
                        +" NIE jest przywracany - sprawdz recznie, jesli zmienialem");
                ok=true;
            } else {
                // ================= KONTROLA HAKOW =================
                println("");
                println("=== KONTROLA HAKOW ===");
                if(!chk(H_ANG,O_ANG,"slot kat      ",S_ANG)) return;
                if(!chk(H_SEL,O_SEL,"slot selektor ",S_SEL)) return;
                for(int k=0;k<4;k++) if(!chk(H_TI[k],O_TI[k],"ti "+TI_CYL[k]+"       ",S_C[k])) return;
                if(!chk(H_ZW,O_ZW,"KFZW          ",S_ZWP)) return;
                if(!chk(H_LB,O_LB,"KFLBTS        ",S_LBP)) return;
                if(!chk(H_RS,O_RS,"KFRLSNT       ",S_RSP)) return;
                if(!chk(H_MIL,O_MIL,"lampka MIL    ",S_MIL)) return;
                if(!chk(H_AZ ,O_AZ ,"maska zaplonu ",S_AZ )) return;
                // mnoznik na plsol_w wycofany - jesli hak tam jeszcze siedzi, przywroc oryginal
                if((mem.getByte(at(H_PL))&0xFF)==0xDA){
                    wr(H_PL,tob(O_PL)); dis(H_PL);
                    println("   plsol_w       @0x"+Long.toHexString(H_PL)
                            +"  hak WYCOFANY, przywrocony bajt seryjny"); }

                // ================= OBSZAR STUBOW (rozproszony) =================
                println("");
                println("=== OBSZAR STUBOW (rozproszony po 3 oknach) ===");
                // Stuby i decoye leza rozrzucone w trzech oknach; przed przebudowa
                // czyscimy je w calosci do 0xFF (to nasza wylaczna przestrzen robocza,
                // w oryginale wolna). CAL i multimapa sa POZA oknami - nie ruszamy ich.
                wipeWindows();
                // stary contiguous blok stubow i legacy obszar tez do 0xFF
                byte[] ffold=new byte[(int)(S_OLD_HI-S_OLD_LO)]; Arrays.fill(ffold,(byte)0xFF); wr(S_OLD_LO,ffold);
                if((mem.getByte(at(OLD_LO))&0xFF)==0xDA){
                    byte[] ffo=new byte[(int)(OLD_HI-OLD_LO)]; Arrays.fill(ffo,(byte)0xFF); wr(OLD_LO,ffo); }
                allocInit();
                for(long[] w:WIN) println(String.format("   okno 0x%06X..0x%06X (%d B wolne)",w[0],w[1]-1,(int)(w[1]-w[0])));

                // ================= TABLICA CAL =================
                println("");
                println("=== TABLICA KALIBRACYJNA ===");
                int verNow=(mem.getByte(at(CAL_VER_A))&0xFF)|((mem.getByte(at(CAL_VER_A+1))&0xFF)<<8);
                boolean clean=isFF(CAL_BASE,CAL_VER_A+2);
                if(verNow==CAL_VER && !clean){
                    println("   tablica JUZ ISTNIEJE, schemat v"+CAL_VER+" - zostawiam wartosci bez zmian");
                    println("   (tak ma byc: twoje ustawienia z WinOLS przezywaja przebudowe)");
                } else {
                    if(!clean){
                        println("   !!! NIEZGODNY SCHEMAT TABLICY !!!");
                        println("   w pliku jest v"+verNow+", kod oczekuje v"+CAL_VER+".");
                        println("   UKLAD tablicy sie zmienil, wiec stare bajty znaczylyby");
                        println("   co innego pod nowymi nazwami. Przesiewam wartosciami");
                        println("   domyslnymi - JESLI COS TAM PRZESTRAJALES, ZAPISZ TO SOBIE");
                        println("   I WPROWADZ PONOWNIE po nowych adresach z mappacku.");
                        byte[] wipe=new byte[(int)(CAL_VER_A+2-CAL_BASE)];
                        Arrays.fill(wipe,(byte)0xFF); wr(CAL_BASE,wipe); }
                    byte[] t=new byte[CAL_N*2];
                    for(int i=0;i<CAL_N;i++){ int v=Integer.parseInt(CAL[i][5],16);
                        t[2*i]=(byte)(v&0xFF); t[2*i+1]=(byte)((v>>8)&0xFF); }
                    wr(CAL_BASE,t);
                    wr(CAL_VER_A,new byte[]{(byte)(CAL_VER&0xFF),(byte)((CAL_VER>>8)&0xFF)});
                    println("   zasiana wartosciami domyslnymi, "+CAL_N+" slow @0x"
                            +Long.toHexString(CAL_BASE)+" (operand "+cw(0)+"), schemat v"+CAL_VER); }
                // ENABLE zgodnie z wyborem w GUI
                int en=0;
                if(doLC)   en|=0x01; if(doNLS) en|=0x02; if(doSEL) en|=0x04; if(doMM) en|=0x08;
                if(doGEAR) en|=0x10; if(doSTR) en|=0x20; if(doRLC) en|=0x40;
                wr(calAddr(C_EN),new byte[]{(byte)(en&0xFF),(byte)((en>>8)&0xFF)});
                println(String.format("   ENABLE = 0x%04X", en));
                println("      bit0 LC .................. "+yn(doLC));
                println("      bit1 NLS ................. "+yn(doNLS));
                println("      bit2 selektor + lampka ... "+yn(doSEL));
                println("      bit3 multimapa 3 banki ... "+yn(doMM));
                println("      bit4 sufit po biegu ...... "+yn(doGEAR));
                println("      bit5 strategie ciecia .... "+yn(doSTR));
                println("      bit6 rolling LC .......... "+yn(doRLC));

                // ================= KOPIE MAP =================
                println("");
                println("=== KOPIE MAP (multimapa) ===");
                if(isFF(HOLE_LO,HOLE_HI)){
                    wr(ZW_B1,rd(MAP_ZW,SZ_ZW)); wr(ZW_B2,rd(MAP_ZW,SZ_ZW));
                    wr(LB_B1,rd(MAP_LB,SZ_LB)); wr(LB_B2,rd(MAP_LB,SZ_LB));
                    int[] zp={ptr16(MAP_ZW),ptr16(ZW_B1),ptr16(ZW_B2)};
                    byte[] tz=new byte[6];
                    for(int k=0;k<3;k++){ tz[2*k]=(byte)(zp[k]&0xFF); tz[2*k+1]=(byte)((zp[k]>>8)&0xFF); }
                    wr(T_ZW,tz);
                    int[] lo2={(int)(MAP_LB&0x3FFF),(int)(LB_B1&0x3FFF),(int)(LB_B2&0x3FFF)};
                    byte[] to=new byte[6];
                    for(int k=0;k<3;k++){ to[2*k]=(byte)(lo2[k]&0xFF); to[2*k+1]=(byte)((lo2[k]>>8)&0xFF); }
                    wr(T_LBOFF,to);
                    wr(T_LBPG,new byte[]{(byte)(MAP_LB>>14),(byte)(LB_B1>>14),(byte)(LB_B2>>14)});
                    println("   zasiane danymi seryjnymi - wszystkie trzy banki startuja identycznie");
                } else {
                    println("   obszar zajety - kopie i tabele ZOSTAWIAM bez zmian (twoje mapy przezywaja)"); }

                println("");
                println("=== KOPIE KFRLSNT (sufit napelnienia) ===");
                if(isFF(RS_B1,RS_B1+SZ_RS) && isFF(RS_B2,RS_B2+SZ_RS) && isFF(T_RS,T_RS+6)){
                    wr(RS_B1, rd(RS_SRC,SZ_RS));
                    wr(RS_B2, rd(RS_SRC,SZ_RS));
                    int[] ro={ RS_OFF0, (int)(RS_B1&0x3FFF), (int)(RS_B2&0x3FFF) };
                    byte[] tr=new byte[6];
                    for(int k=0;k<3;k++){ tr[2*k]=(byte)(ro[k]&0xFF); tr[2*k+1]=(byte)((ro[k]>>8)&0xFF); }
                    wr(T_RS,tr);
                    println("   zasiane danymi seryjnymi - wszystkie trzy banki maja ten sam sufit");
                    println(String.format("   bank0 offset 0x%04X (seryjny)  bank1 0x%04X  bank2 0x%04X",
                            ro[0],ro[1],ro[2]));
                } else {
                    println("   obszar zajety - kopie i tabela ZOSTAJA bez zmian"); }

                // ---- sufit napelnienia PO BIEGU: 6 kopii + tablica wskaznikow ----
                println("");
                println("=== KOPIE KFRLSNT PO BIEGU ===");
                if(isFF(RG_BASE,RG_BASE+RG_N*SZ_RS) && isFF(T_GEAR,T_GEAR+2L*RG_N)){
                    byte[] tg=new byte[2*RG_N];
                    StringBuilder sb2=new StringBuilder();
                    for(int g=0;g<RG_N;g++){
                        long a=RG_BASE+(long)g*SZ_RS;
                        wr(a, rd(RS_SRC,SZ_RS));
                        int off=(int)(a&0x3FFF);
                        tg[2*g]=(byte)(off&0xFF); tg[2*g+1]=(byte)((off>>8)&0xFF);
                        sb2.append(String.format(" bieg%d=0x%04X",g+1,off)); }
                    wr(T_GEAR,tg);
                    println("   zasiane danymi seryjnymi - kazdy bieg startuje z sufitem seryjnym");
                    println("  "+sb2.toString());
                } else {
                    println("   obszar zajety - kopie i tabela ZOSTAJA bez zmian"); }

                // ---- tablica odwracania nibbla maski (paliwo -> zaplon) ----
                println("");
                println("=== TABLICA ODWRACANIA MASKI ===");
                byte[] rev=new byte[16];
                for(int mki=0;mki<16;mki++){
                    int r=0;
                    for(int kk=0;kk<4;kk++) if(((mki>>kk)&1)!=0) r|=(1<<(3-kk));
                    rev[mki]=(byte)r; }
                wr(T_REV,rev);
                StringBuilder sbr=new StringBuilder();
                for(int mki=0;mki<16;mki++) sbr.append(String.format("%X->%X ",mki,rev[mki]&0xF));
                println("   @0x"+Long.toHexString(T_REV)+" (operand "+O_REVT+"):  "+sbr.toString().trim());

                // ================= STUBY (rozproszone) =================
                // FAZA 1: pomiar rozmiarow. S_* sa jeszcze dummy, ale 'calls' do innego
                // stuba ma 4 B niezaleznie od celu, wiec zmierzone rozmiary sa poprawne.
                int szA=asmbObf(0x0CC000L,angStub(),"ANG").length;
                int szM=asmbObf(0x0CC000L,maskStub(),"MASK").length;
                int szS=asmbObf(0x0CC000L,selStub(),"SEL").length;
                int szZ=asmbObf(0x0CC000L,ptrStub(O_ZWT,"r12",false),"ZW").length;
                int szL=asmbObf(0x0CC000L,lbStub(),"LB").length;
                int szP=asmbObf(0x0CC000L,rsStub(),"RS").length;
                int szI=asmbObf(0x0CC000L,milStub(),"MIL").length;
                int szX=asmbObf(0x0CC000L,azStub(),"AZ").length;
                int szR=asmbObf(0x0CC000L,rlcStub(),"RLC").length;
                int szT=asmbObf(0x0CC000L,routeStub(),"ROU").length;
                int[] szC=new int[4];
                for(int k=0;k<4;k++) szC[k]=asmbObf(0x0CC000L,tiStub(k),"TI"+k).length;

                // FAZA 2: przydzial rozproszonych baz ze WSPOLNEGO alokatora. Preferencje
                // okien tak dobrane, by realne stuby wpadly TEZ do W_B i W_C (przeplot z
                // decoyami), a duze zostaly w W_A. allocFit robi fallback, gdy okno pelne.
                S_ANG =allocFit(0,szA);
                S_CM  =allocFit(1,szM);          // pref W_B
                S_C[0]=allocFit(2,szC[0]);       // pref W_C
                S_C[1]=allocFit(0,szC[1]);
                S_C[2]=allocFit(1,szC[2]);       // pref W_B
                S_C[3]=allocFit(0,szC[3]);
                S_SEL =allocFit(0,szS);
                S_ZWP =allocFit(0,szZ);
                S_LBP =allocFit(0,szL);
                S_RSP =allocFit(0,szP);
                S_MIL =allocFit(2,szI);          // pref W_C
                S_AZ  =allocFit(0,4+szX);        // O_AZ (4 B) + azStub
                S_RLC =allocFit(1,szR);          // pref W_B
                S_ROU =allocFit(0,szT);

                // FAZA 3: regeneracja z FINALNYMI S_* (calls miedzy stubami celuja teraz
                // poprawnie), asemblacja na finalnej bazie, zapis.
                byte[] cA=asmbObf(S_ANG,angStub(),"ANG");
                byte[] cM=asmbObf(S_CM ,maskStub(),"MASK");
                byte[] cS=asmbObf(S_SEL,selStub(),"SEL");
                byte[] cZ=asmbObf(S_ZWP,ptrStub(O_ZWT,"r12",false),"ZW");
                byte[] cL=asmbObf(S_LBP,lbStub(),"LB");
                byte[] cP=asmbObf(S_RSP,rsStub(),"RS");
                byte[] cI=asmbObf(S_MIL,milStub(),"MIL");
                byte[] cX=asmbObf(S_AZ+4,azStub(),"AZ");
                byte[] cR=asmbObf(S_RLC,rlcStub(),"RLC");
                byte[] cT=asmbObf(S_ROU,routeStub(),"ROU");
                byte[][] cC=new byte[4][];
                for(int k=0;k<4;k++) cC[k]=asmbObf(S_C[k],tiStub(k),"TI"+k);
                // pewnosc: rozmiar z fazy 3 == faza 1 (inaczej przydzial by sie rozjechal)
                if(cA.length!=szA||cM.length!=szM||cS.length!=szS||cZ.length!=szZ||cL.length!=szL
                   ||cP.length!=szP||cI.length!=szI||cX.length!=szX||cR.length!=szR||cT.length!=szT)
                    throw new Exception("STOP: rozmiar stuba zmienil sie miedzy faza 1 a 3");
                for(int k=0;k<4;k++) if(cC[k].length!=szC[k]) throw new Exception("STOP: rozmiar ti"+k+" sie zmienil");

                wr(S_ANG,cA); wr(S_CM,cM); wr(S_SEL,cS);
                for(int k=0;k<4;k++) wr(S_C[k],cC[k]);
                wr(S_ZWP,cZ); wr(S_LBP,cL); wr(S_RSP,cP); wr(S_MIL,cI);
                wr(S_AZ,tob(O_AZ)); wr(S_AZ+4,cX); wr(S_RLC,cR); wr(S_ROU,cT);
                println("");
                println("=== ROZPROSZENIE STUBOW (bazy przydzielone) ===");
                println(String.format("   kat 0x%06X  maska 0x%06X  sel 0x%06X  KFZW 0x%06X",S_ANG,S_CM,S_SEL,S_ZWP));
                println(String.format("   KFLBTS 0x%06X  KFRLSNT 0x%06X  MIL 0x%06X  azmaska 0x%06X",S_LBP,S_RSP,S_MIL,S_AZ));
                println(String.format("   rollingLC 0x%06X  router 0x%06X  ti[0..3] 0x%06X/0x%06X/0x%06X/0x%06X",
                        S_RLC,S_ROU,S_C[0],S_C[1],S_C[2],S_C[3]));

                wr(H_ANG,asm.assembleLine(at(H_ANG),"calls 0x"+Long.toHexString(S_ANG)));
                wr(H_SEL,asm.assembleLine(at(H_SEL),"calls 0x"+Long.toHexString(S_SEL)));
                for(int k=0;k<4;k++)
                    wr(H_TI[k],asm.assembleLine(at(H_TI[k]),"calls 0x"+Long.toHexString(S_C[k])));
                wr(H_ZW,asm.assembleLine(at(H_ZW),"calls 0x"+Long.toHexString(S_ZWP)));
                wr(H_LB,asm.assembleLine(at(H_LB),"calls 0x"+Long.toHexString(S_LBP)));
                wr(H_RS,asm.assembleLine(at(H_RS),"calls 0x"+Long.toHexString(S_RSP)));
                wr(H_MIL,asm.assembleLine(at(H_MIL),"calls 0x"+Long.toHexString(S_MIL)));
                wr(H_AZ ,asm.assembleLine(at(H_AZ ),"calls 0x"+Long.toHexString(S_AZ )));

                if((mem.getByte(at(AZYTIAB))&0xFF)!=0) wr(AZYTIAB,new byte[]{(byte)0x00});

                dis(S_ANG); dis(S_CM); dis(S_SEL); dis(S_ZWP); dis(S_LBP); dis(S_RSP); dis(S_MIL); dis(S_AZ+4); dis(S_RLC); dis(S_ROU);
                for(int k=0;k<4;k++){ dis(S_C[k]); dis(H_TI[k]); }
                dis(H_ANG); dis(H_SEL); dis(H_ZW); dis(H_LB); dis(H_RS); dis(H_MIL); dis(H_AZ);
                try{ prog.getSymbolTable().createLabel(at(CAL_BASE),"CAL_ME76",SourceType.USER_DEFINED);}catch(Exception e){}

                println("");
                println("=== STUB KATA ("+cA.length+" B) ===");        dump(S_ANG,S_ANG+cA.length);
                println("=== MASKA ("+cM.length+" B) ===");            dump(S_CM,S_CM+cM.length);
                println("=== SELEKTOR ("+cS.length+" B) ===");         dump(S_SEL,S_SEL+cS.length);
                println("=== WSKAZNIK KFZW ("+cZ.length+" B) ===");    dump(S_ZWP,S_ZWP+cZ.length);
                println("=== WSKAZNIK KFLBTS ("+cL.length+" B) ===");  dump(S_LBP,S_LBP+cL.length);
                println("=== WSKAZNIK KFRLSNT ("+cP.length+" B) ==="); dump(S_RSP,S_RSP+cP.length);
                println("=== LAMPKA MIL ("+cI.length+" B) ===");      dump(S_MIL,S_MIL+cI.length);
                println("=== MASKA ZAPLONU ("+(4+cX.length)+" B) ==="); dump(S_AZ,S_AZ+4+cX.length);
                println("=== ROLLING LC ("+cR.length+" B) ===");        dump(S_RLC,S_RLC+cR.length);
                println("=== ROUTER STRATEGII ("+cT.length+" B) ==="); dump(S_ROU,S_ROU+cT.length);
                println("=== STUB ti0 ("+cC[0].length+" B) ===");      dump(S_C[0],S_C[0]+cC[0].length);

                // ================= FALSZYWY KOD (decoy) =================
                // Rozrzucony po trzech rekordach sumy, spiety w pierscien calls.
                // Wewnatrz transakcji, wiec suma go obejmie przy eksporcie.
                writeDecoys();
                ok=true;
            }

            println("");
            println("=== LISTA ZMIAN (offsety w pliku) ===");
            for(String x:plist) println(x);
        } finally { prog.endTransaction(txn,ok); }
        if(!ok){ prog.release(this); return; }
        try{ prog.save("studio",monitor); }catch(Exception e){}

                // ================= ZNAK WODNY =================
                if(doWM) writeWatermark();

                // ================= EKSPORT =================
        MemoryBlock fb2=fblk(); long bs=fb2.getStart().getOffset(); int sz=(int)fb2.getSize();
        byte[] img=new byte[sz];
        for(int i=0;i<sz;i++) img[i]=mem.getByte(sp.getAddress(bs+i));
        String nm=prog.getName(); int d=nm.lastIndexOf('.'); if(d>0) nm=nm.substring(0,d);
        nm=nm.replaceAll("[\\\\/:*?\"<>|]","_");
        File dir=outDir();
        File out=new File(dir,nm+(doREV?"_SERYJNY":"_STUDIO")+".bin");
        fixSums(img);
        FileOutputStream os=new FileOutputStream(out); try{ os.write(img);} finally{ os.close(); }
        println("");
        println("############################################################");
        println("# BIN : "+out.getAbsolutePath()+"   ("+sz+" B)");
        println("############################################################");
        byte[] ch=java.nio.file.Files.readAllBytes(out.toPath());
        println("KONTROLA HAKOW (odczyt z dysku):");
        long[] hs={H_ANG,H_SEL,H_TI[0],H_TI[1],H_TI[2],H_TI[3],H_ZW,H_LB,H_RS,H_MIL,H_AZ};
        long[] ts={S_ANG,S_SEL,S_C[0],S_C[1],S_C[2],S_C[3],S_ZWP,S_LBP,S_RSP,S_MIL,S_AZ};
        String[] hn={"slot kat","slot selektor","ti cyl1","ti cyl3","ti cyl4","ti cyl2",
                     "KFZW","KFLBTS","KFRLSNT","lampka MIL","maska zaplonu"};
        for(int k=0;k<hs.length;k++){ StringBuilder sb=new StringBuilder();
            for(int i=0;i<4;i++) sb.append(String.format("%02X ",ch[(int)(hs[k]-fbase+i)]&0xFF));
            String want=doREV?"(seryjne)":callsHex(ts[k]);
            println(String.format("   +0x%06X  %-14s %-14s %s",hs[k]-fbase,hn[k],
                    sb.toString().trim(),"ma byc "+want)); }

        // ================= MAPPACK =================
        if(doCSV){
            File csv=new File(dir,nm+"_mappack.csv");
            writeMappack(csv,ch,vin);
            println("");
            println("# MAPPACK : "+csv.getAbsolutePath());
            println("#   adresy jako "+(MP_FILE_OFFSET
                    ? "OFFSET W PLIKU - importuj BEZ dodatkowego offsetu"
                    : "ADRES CHIPOWY - przy imporcie ustaw offset 0x10000"));
            println("#   KOLEJNOSC BAJTOW: LSB_FIRST (Intel / LoHi).");
            println("#   W a2lgen ODZNACZ checkbox 'MSB_FIRST (big endian)',");
            println("#   inaczej osie nmot/rl i caly KFRLSNT wyjda jako smieci.");
        }
        println("");
        println(">>> sumy kontrolne poprawione w tym pliku - gotowy do wgrania <<<");
        prog.release(this);
    }

    static String yn(boolean b){ return b?"tak":"nie"; }
    static byte[] tob(int[] a){ byte[] b=new byte[a.length];
        for(int i=0;i<a.length;i++) b[i]=(byte)a[i]; return b; }
    void fit(String nm,long base,int len,long lim) throws Exception {
        if(base+len>lim) throw new Exception("stub '"+nm+"' za dlugi: "+len
            +" B, miejsca "+(lim-base)+" B"); }
    // ================= SUMY KONTROLNE =================
    // ME7.6.2 trzyma tablice sum wielopunktowych pod adresem chipowym 0x0BFB80
    // (offset w pliku 0x0AFB80). Rekord ma 16 bajtow: start(4) koniec(4) suma(4)
    // ~suma(4), adresy chipowe, wszystko little-endian. Suma to 32-bitowe
    // dodawanie SLOW 16-bitowych LE z zakresu wlacznie z koncem.
    //
    // Sama tablica lezy wewnatrz zakresu nr 35 (0x0BC000..0x0BFFFF), wiec z pozoru
    // jest tu blednne kolo. Nie ma: para suma + ~suma to w sumie slow zawsze
    // 0xFFFF + 0xFFFF niezaleznie od wartosci, czyli wklad do sumy zakresu jest
    // STALY. Dlatego jeden przebieg wystarcza i nie trzeba iterowac.
    //
    // Dwa pierwsze rekordy (0x000000..0x007FFF) to sektor bootloadera, ktorego
    // nie ma w pliku i ktorego programator nie pisze - zostawiamy nietkniete.
    static final long SUM_TBL = 0x0AFB80L;   // offset w pliku
    static final int  SUM_N   = 48;
    // Obok tablicy wielopunktowej sa jeszcze TRZY rekordy "glowne" pod 0x0A0374.
    // Ten sam uklad i ta sama arytmetyka, tylko lezaca osobno. Dotad zgadzaly sie
    // same z siebie, bo zaden hak nie wpada w ich zakresy - ale to jest zbieg
    // okolicznosci, nie zabezpieczenie. Przy nastepnym haku w segmencie 0x02xxxx
    // albo 0x0B03xx plik wyszedlby po cichu zepsuty. Dlatego sprawdzamy je jawnie.
    static final long[] SUM_MAIN = { 0x0A037AL, 0x0A038AL, 0x0A039AL };

    static int u32(byte[] b,int i){
        return (b[i]&0xFF) | ((b[i+1]&0xFF)<<8) | ((b[i+2]&0xFF)<<16) | ((b[i+3]&0xFF)<<24); }
    static void p32(byte[] b,int i,int v){
        b[i]=(byte)v; b[i+1]=(byte)(v>>8); b[i+2]=(byte)(v>>16); b[i+3]=(byte)(v>>24); }
    static int sum16(byte[] b,int a,int e){
        int s=0;
        for(int i=a;i+1<=e;i+=2) s += (b[i]&0xFF) | ((b[i+1]&0xFF)<<8);
        if(((e-a+1)&1)!=0) s += (b[e]&0xFF);
        return s; }

    // Buduje 64 B markera. Wydzielone, bo teraz sa TRZY kopie w roznych rekordach.
    byte[] buildWatermark() throws Exception {
        byte[] w = new byte[64];
        Arrays.fill(w,(byte)0x00);
        int p=0;
        for(byte mb: WM_MAGIC) w[p++]=mb;      // 0..5  magia "ME76WM"
        w[p++]=(byte)WM_VER;                    // 6     wersja formatu
        w[p++]=(byte)0x00;                      // 7     rezerwa
        w[p++]=(byte)(wmSerial&0xFF);           // 8..11 serial u32 LE (runtime)
        w[p++]=(byte)((wmSerial>>8)&0xFF);
        w[p++]=(byte)((wmSerial>>16)&0xFF);
        w[p++]=(byte)((wmSerial>>24)&0xFF);
        p=12;
        byte[] ow=WM_OWNER.getBytes("US-ASCII");         // 12..27  wlasciciel (16)
        for(int i=0;i<16 && i<ow.length;i++) w[12+i]=ow[i];
        byte[] tg=WM_TARGET.getBytes("US-ASCII");        // 28..47  klient (20)
        for(int i=0;i<20 && i<tg.length;i++) w[28+i]=tg[i];
        String d=new java.text.SimpleDateFormat("yyyyMMdd").format(new java.util.Date());
        byte[] db=d.getBytes("US-ASCII");                // 48..55  data budowy (8)
        for(int i=0;i<8 && i<db.length;i++) w[48+i]=db[i];
        // 56..63: odcisk kontrolny samego markera (fold slow 16-bit z 56..57=0),
        // zeby przypadkowa edycja pola byla widoczna. To NIE jest zabezpieczenie,
        // tylko sanity - suma pliku i tak chroni caly blok.
        int fold=0;
        for(int i=0;i<56;i+=2) fold += (w[i]&0xFF)|((w[i+1]&0xFF)<<8);
        w[56]=(byte)(fold&0xFF); w[57]=(byte)((fold>>8)&0xFF);
        w[58]=(byte)0x00; w[59]=(byte)0x00;
        w[60]=(byte)0x00; w[61]=(byte)0x00; w[62]=(byte)0x00; w[63]=(byte)0x00;
        return w;
    }

    void writeWatermark() throws Exception {
        println("");
        println("=== ZNAK WODNY (3 kopie) ===");
        if(clientMode){ wmSerial=nextClientSerial(outDir());
            println("   [tryb klienta] serial auto z licznika me76_serial.txt"); }
        byte[] w = buildWatermark();
        String d=new java.text.SimpleDateFormat("yyyyMMdd").format(new java.util.Date());
        wr(WM_BASE, w);
        wr(WM_BASE2, w);
        wr(WM_BASE3, w);
        println(String.format("   kopia 1 @ chip 0x%06X (plik 0x%06X), rekord sumy 33",
                WM_BASE,  WM_BASE -fbase));
        println(String.format("   kopia 2 @ chip 0x%06X (plik 0x%06X), rekord sumy 35",
                WM_BASE2, WM_BASE2-fbase));
        println(String.format("   kopia 3 @ chip 0x%06X (plik 0x%06X), rekord sumy 3",
                WM_BASE3, WM_BASE3-fbase));
        println("   magia   : ME76WM  wersja "+WM_VER);
        println(String.format("   serial  : 0x%08X (%d)", wmSerial, wmSerial));
        println("   wlasciciel: "+WM_OWNER);
        println("   klient    : "+(WM_TARGET.isEmpty()?"(kopia wlasna)":WM_TARGET));
        println("   data      : "+d);
        println("   >>> ZAPISZ W REJESTRZE: serial "+wmSerial+" -> "
                +(WM_TARGET.isEmpty()?"kopia wlasna":WM_TARGET)+" ("+d+")");
        StringBuilder hx=new StringBuilder();
        for(int i=0;i<64;i++){ hx.append(String.format("%02X ",w[i]&0xFF)); if((i&0xF)==0xF) hx.append("\n            "); }
        println("   bajty   : "+hx.toString().trim());
    }

    // ===== FALSZYWY KOD (decoy) =====
    // Jedno cialo decoy: wyglada jak drabinka LC/rolling-LC. Uzywa wylacznie form
    // instrukcji, ktore realne stuby juz asemblowaly, wiec kodowanie jest pewne.
    // Zapisy ida do martwego XRAM 0xaf50+ (nic tego nie czyta). Immediate i adresy
    // losowane z deterministycznego strumienia (rng) -> kazdy decoy inny, ale SHA
    // pliku stabilne. Etykiety prefiksowane L, zeby nie kolidowaly miedzy blokami.
    List<String> decoyBody(java.util.Random rng, String L){
        String[] W ={NMOT_W,"0x80b1","0xf837","0xf7c8","0xf742"};   // czytania slow
        String[] B ={FGRBTN,"0x8413","0x83bf","0xf837"};             // czytania bajtow
        String[] CC={"cc_NC","cc_C","cc_UGT","cc_ULE"};
        long[]  SINK={0xaf50L,0xaf52L,0xaf54L,0xaf56L,0xaf58L};      // martwy XRAM
        List<String> a=new ArrayList<String>();
        a.add("push r6"); a.add("push r5"); a.add("push r4");
        a.add("mov r5,"+W[rng.nextInt(W.length)]);
        a.add("mov r6,#0x"+Integer.toHexString(0x1000+rng.nextInt(0x6000)));
        a.add("cmp r5,r6");
        a.add("jmpr "+CC[rng.nextInt(2)]+",@"+L+"_1");
        a.add("movb RL5,"+B[rng.nextInt(B.length)]);
        a.add("movb RH5,#0x0");
        a.add("mov r6,#0x"+Integer.toHexString(1+rng.nextInt(0x40)));
        a.add("cmpb RL5,RL6");
        a.add("jmpr "+CC[2+rng.nextInt(2)]+",@"+L+"_2");
        a.add("movb RL4,#0x"+Integer.toHexString(rng.nextInt(0x40)));
        a.add("shl r5,#0x1");
        a.add("mov 0x"+Long.toHexString(SINK[rng.nextInt(SINK.length)])+",r5");
        a.add("jmpr cc_UC,@"+L+"_3");
        a.add(L+"_1:");
        a.add("movb RL5,"+B[rng.nextInt(B.length)]);
        a.add("mov r6,#0x"+Integer.toHexString(1+rng.nextInt(0x30)));
        a.add("add r6,r5");
        a.add("movb 0x"+Long.toHexString(SINK[rng.nextInt(SINK.length)])+",RL5");
        a.add(L+"_2:");
        a.add("mov r5,#0x0");
        a.add("mov 0x"+Long.toHexString(SINK[rng.nextInt(SINK.length)])+",r5");
        a.add(L+"_3:");
        a.add("pop r4"); a.add("pop r5"); a.add("pop r6");
        a.add("rets");
        return a;
    }
    // Wstawia 'calls 0x<t>' tuz przed koncowym rets (spiecie w pierscien).
    List<String> withCall(List<String> body, long t){
        List<String> o=new ArrayList<String>(body);
        for(int i=o.size()-1;i>=0;i--)
            if(o.get(i).trim().equalsIgnoreCase("rets")){
                o.add(i,"calls 0x"+Long.toHexString(t)); break; }
        return o;
    }
    void writeDecoys() throws Exception {
        println("");
        println("=== FALSZYWY KOD (decoy) ===");
        java.util.Random rng=new java.util.Random(D_SEED);
        List<List<String>> bodies=new ArrayList<List<String>>();
        for(int i=0;i<DEC_N;i++) bodies.add(decoyBody(rng,"L"+i));
        // 1) rozmiary z placeholderem calls (calls ma stale 4 B niezaleznie od celu)
        int[] sz=new int[DEC_N];
        for(int i=0;i<DEC_N;i++)
            sz[i]=asmb(0x0CC000L, withCall(bodies.get(i),0x0CC000L).toArray(new String[0])).length;
        // 2) przydzial ze WSPOLNEGO alokatora (po stubach) -> decoye przeplecione z
        //    realnym kodem. Round-robin preferencji okien dla rozrzutu po rekordach.
        long[] addr=new long[DEC_N];
        for(int i=0;i<DEC_N;i++) addr[i]=allocFit(i%WIN.length, sz[i]);
        // 3) pierscien: decoy i wola decoy (i+1)%N; assembluj na finalnej bazie i zapisz
        for(int i=0;i<DEC_N;i++){
            long next=addr[(i+1)%DEC_N];
            byte[] code=asmb(addr[i], withCall(bodies.get(i),next).toArray(new String[0]));
            if(code.length!=sz[i]) throw new Exception("decoy "+i+" zmienil rozmiar");
            wr(addr[i],code); dis(addr[i]);
            println(String.format("   decoy %d @0x%06X (plik 0x%06X, %d B) -> calls 0x%06X",
                    i, addr[i], addr[i]-fbase, code.length, next));
        }
        println("   (bloki spiete w pierscien calls, brak wejscia z zywego kodu - nie wykonuja sie)");
    }

    void fixSums(byte[] img){
        println("");
        println("=== SUMY KONTROLNE ===");
        int t=(int)SUM_TBL, fixed=0, skipped=0;
        for(int k=0;k<SUM_N;k++){
            int i=t+16*k;
            long s=u32(img,i)&0xFFFFFFFFL, e=u32(img,i+4)&0xFFFFFFFFL;
            int c=u32(img,i+8), ic=u32(img,i+12);
            if((c^ic)!=0xFFFFFFFF){ println("   rekord "+k+": brak pary suma/~suma - koniec tablicy"); break; }
            long fa=s-fbase, fe=e-fbase;
            if(fa<0 || fe>=img.length){ skipped++; continue; }
            int nw=sum16(img,(int)fa,(int)fe);
            if(nw!=c){
                p32(img,i+8,nw); p32(img,i+12,~nw);
                println(String.format("   %2d  chip %06X..%06X  0x%08X -> 0x%08X",k,s,e,c,nw));
                fixed++; } }
        // kontrola po korekcie - jesli cokolwiek tu wyjdzie, NIE WOLNO tego wgrywac
        int bad=0;
        for(int k=0;k<SUM_N;k++){
            int i=t+16*k;
            long s=u32(img,i)&0xFFFFFFFFL, e=u32(img,i+4)&0xFFFFFFFFL;
            int c=u32(img,i+8);
            if((c^u32(img,i+12))!=0xFFFFFFFF) break;
            long fa=s-fbase, fe=e-fbase;
            if(fa<0 || fe>=img.length) continue;
            if(sum16(img,(int)fa,(int)fe)!=c){ bad++;
                println("   !!! rekord "+k+" DALEJ SIE NIE ZGADZA"); } }
        // ---- rekordy glowne ----
        int mfix=0, mbad=0, mskip=0;
        for(int k=0;k<SUM_MAIN.length;k++){
            int i=(int)SUM_MAIN[k];
            int c=u32(img,i+8), ic=u32(img,i+12);
            if((c^ic)!=0xFFFFFFFF){
                println("   rekord glowny "+k+" @0x"+Long.toHexString(SUM_MAIN[k])
                        +": brak pary suma/~suma - uklad pliku inny niz zmapowany, NIE RUSZAM");
                mskip++; continue; }
            long s2=u32(img,i)&0xFFFFFFFFL, e2=u32(img,i+4)&0xFFFFFFFFL;
            long fa=s2-fbase, fe=e2-fbase;
            if(fa<0 || fe>=img.length){ mskip++; continue; }
            int nw=sum16(img,(int)fa,(int)fe);
            if(nw!=c){
                p32(img,i+8,nw); p32(img,i+12,~nw);
                println(String.format("   glowna %d  chip %06X..%06X  0x%08X -> 0x%08X",
                        k,s2,e2,c,nw));
                mfix++; }
            if(sum16(img,(int)fa,(int)fe)!=u32(img,i+8)){ mbad++;
                println("   !!! suma glowna "+k+" DALEJ SIE NIE ZGADZA"); } }

        println("   wielopunktowe: poprawionych "+fixed+", pominietych (sektor boot) "+skipped
                +", bledow po korekcie "+bad);
        println("   glowne:        poprawionych "+mfix+", pominietych "+mskip
                +", bledow po korekcie "+mbad);
        if(bad>0 || mbad>0) println("   !!! NIE WGRYWAJ TEGO PLIKU !!!");
        else println("   plik gotowy do wgrania bez zewnetrznego korektora sum");
    }

    File outDir(){
        String ep=prog.getExecutablePath();
        if(ep!=null&&ep.length()>0){
            if(ep.startsWith("/")&&ep.length()>3&&ep.charAt(2)==':') ep=ep.substring(1);
            File f=new File(ep.replace('/',File.separatorChar));
            if(f.getParentFile()!=null&&f.getParentFile().isDirectory()) return f.getParentFile(); }
        return new File(System.getProperty("user.home")); }
    boolean chk(long a,int[] orig,String nm,long stub) throws Exception {
        boolean o=true;
        for(int i=0;i<4;i++) if((mem.getByte(at(a+i))&0xFF)!=orig[i]){ o=false; break; }
        boolean p=(mem.getByte(at(a))&0xFF)==0xDA;
        if(!o&&!p){ println("   STOP: "+nm+" @0x"+Long.toHexString(a)+" ma "+hx(rd(a,4))
            +", a spodziewam sie seryjnego albo naszego calls"); return false; }
        println("   "+nm+" @0x"+Long.toHexString(a)+(o?"  seryjny":"  juz zahaczony")); return true; }

    // ======================= STUBY =======================
    List<String> angStub(){
        List<String> a=new ArrayList<String>();
        a.add("calls 0x"+Long.toHexString(ORIG_ANG));
        a.add("push r4"); a.add("push r5"); a.add("push r6");
        a.add("jb "+KUPPL_R+"."+KUPPL_B+",@A_CLU");
        // --- sprzeglo puszczone: kat dla rolling LC ---
        // Stopien policzyl juz stub maski, tak samo jak przy LC. Zero to "nie tne".
        a.add("mov r6,"+cw(C_EN));
        a.add("jnb r6.6,@A_OUT");
        a.add("movb RL5,"+V_RSTG);
        a.add("cmpb RL5,#0x0");
        a.add("jmpr cc_EQ,@A_OUT");
        a.add("subb RL5,#0x1");
        a.add("movb RH5,#0x0");
        a.add("shl r5,#0x1");
        a.add("mov r6,#"+cw(C_RZW));
        a.add("add r6,r5");
        a.add("movb RL4,[r6]");
        a.add("jmpr cc_UC,@A_WR");
        a.add("A_CLU:");
        a.add("movb RL5,"+VFZG_B);
        a.add("mov r6,"+cw(C_SPD));
        a.add("cmpb RL5,RL6");
        a.add("jmpr cc_NC,@A_NLS");
        // ---- LC: stopien policzyl juz stub maski, my tylko czytamy kat ----
        // Dzieki temu kat i maska ZAWSZE naleza do tego samego stopnia - nie ma
        // szansy, zeby stub maski ciol trzy cylindry, a kat byl jeszcze od dwoch.
        a.add("mov r6,"+cw(C_EN));
        a.add("jnb r6.0,@A_OUT");
        a.add("movb RL5,"+V_LCSTG);
        a.add("cmpb RL5,#0x0");
        a.add("jmpr cc_EQ,@A_OUT");
        a.add("subb RL5,#0x1");
        a.add("movb RH5,#0x0");
        a.add("shl r5,#0x1");
        a.add("mov r6,#"+cw(C_ZW));
        a.add("add r6,r5");
        a.add("movb RL4,[r6]");
        a.add("jmpr cc_UC,@A_WR");
        a.add("A_NLS:");
        a.add("mov r6,"+cw(C_EN));
        a.add("jnb r6.1,@A_OUT");
        a.add("mov r5,"+V_NLSC);
        a.add("mov r6,"+cw(C_NDUR));
        a.add("cmp r5,r6");
        a.add("jmpr cc_NC,@A_OUT");
        a.add("movb RL5,"+RL_B);
        a.add("mov r6,"+cw(C_NRL));
        a.add("cmpb RL5,RL6");
        a.add("jmpr cc_ULE,@A_OUT");
        a.add("movb RL4,"+cw(C_NZW));
        a.add("A_WR:");
        for(String z:ZWOUT) a.add("movb "+z+",RL4");
        a.add("A_OUT:");
        a.add("pop r6"); a.add("pop r5"); a.add("pop r4"); a.add("rets");
        return a;
    }

    List<String> maskStub(){
        List<String> m=new ArrayList<String>();
        m.add("push r6");
        // Maska zaplonu jest skladana od nowa przy kazdym wywolaniu. Gdy nie tniemy,
        // musi byc zerem - inaczej ostatnia wartosc wisialaby w nieskonczonosc.
        m.add("movb RL5,#0x0"); m.add("movb "+V_AZMSK+",RL5");
        m.add("movb "+V_RSTG+",RL5");
        // Sygnalizacja banku nie dotyka juz wtrysku - numer banku pokazuje lampka MIL.
        // Dzieki temu ta sciezka NIGDY nie tnie cylindrow poza LC i NLS, a przelaczanie
        // banku przestalo szarpac obrotami na biegu jalowym.
        m.add("M_NORM:");
        m.add("movb RL4,#0x0");
        m.add("jb "+KUPPL_R+"."+KUPPL_B+",@M_CLU");
        // sprzeglo puszczone -> przezbrojenie NLS
        m.add("movb RL5,#0x0");
        m.add("movb "+V_PREVK+",RL5");
        m.add("movb "+V_LCSTG+",RL5");
        // Sprzeglo puszczone. Dla LC i NLS to koniec, ale rolling LC dziala
        // WLASNIE tutaj - z wpietym napedem. Stub rolling LC sam przepuszcza
        // wynik przez router strategii i oddaje gotowa maske w RL4.
        m.add("calls 0x"+Long.toHexString(S_RLC));
        m.add("pop r6"); m.add("rets");
        m.add("M_CLU:");
        // --- ocena okna NLS RAZ, na zboczu ---
        m.add("mov r6,"+cw(C_EN));
        m.add("jnb r6.1,@M_SPD");
        m.add("movb RL5,"+V_PREVK);
        m.add("cmpb RL5,#0x0");
        m.add("jmpr cc_NE,@M_SPD");
        m.add("movb RL5,#0x1");
        m.add("movb "+V_PREVK+",RL5");
        m.add("mov r5,"+NMOT_W);
        m.add("mov r6,"+cw(C_NMIN));
        m.add("cmp r5,r6");
        m.add("jmpr cc_C,@M_NARM");
        m.add("mov r6,"+cw(C_NMAX));
        m.add("cmp r5,r6");
        m.add("jmpr cc_UGT,@M_NARM");
        m.add("mov r5,#0x0");
        m.add("mov "+V_NLSC+",r5");
        m.add("jmpr cc_UC,@M_SPD");
        m.add("M_NARM:");
        m.add("mov r5,#0xffff");
        m.add("mov "+V_NLSC+",r5");
        // --- postoj czy jazda ---
        m.add("M_SPD:");
        m.add("movb RL5,"+VFZG_B);
        m.add("mov r6,"+cw(C_SPD));
        m.add("cmpb RL5,RL6");
        m.add("jmpr cc_NC,@M_NLS");
        // ---- LC: DRABINKA STOPNI ----
        // Stopien liczymy od gory, bo pierwsze trafienie konczy sprawe.
        // 0 w V_LCSTG znaczy "LC nieaktywny" - stub kata wtedy nie rusza zaplonu.
        m.add("mov r6,"+cw(C_EN));
        m.add("jnb r6.0,@M_LCOFF");
        m.add("mov r5,"+NMOT_W);
        m.add("mov r6,"+cw(C_TH+3));
        m.add("cmp r5,r6");
        m.add("jmpr cc_NC,@M_L4");
        m.add("mov r6,"+cw(C_TH+2));
        m.add("cmp r5,r6");
        m.add("jmpr cc_NC,@M_L3");
        m.add("mov r6,"+cw(C_TH+1));
        m.add("cmp r5,r6");
        m.add("jmpr cc_NC,@M_L2");
        m.add("mov r6,"+cw(C_TH));
        m.add("cmp r5,r6");
        m.add("jmpr cc_NC,@M_L1");
        m.add("M_LCOFF:");                       // ponizej progu 1 albo LC wylaczony
        m.add("movb RL5,#0x0");
        m.add("movb "+V_LCSTG+",RL5");
        m.add("pop r6"); m.add("rets");
        m.add("M_L4:"); m.add("movb RL5,#0x4"); m.add("jmpr cc_UC,@M_STG");
        m.add("M_L3:"); m.add("movb RL5,#0x3"); m.add("jmpr cc_UC,@M_STG");
        m.add("M_L2:"); m.add("movb RL5,#0x2"); m.add("jmpr cc_UC,@M_STG");
        m.add("M_L1:"); m.add("movb RL5,#0x1");
        m.add("M_STG:");
        m.add("movb "+V_LCSTG+",RL5");
        m.add("subb RL5,#0x1");                  // indeks w tablicach = stopien-1
        m.add("movb RH5,#0x0");
        m.add("shl r5,#0x1");                    // tablice sa u16
        // rotacja polowek po bicie 2 anzti: w jednym cyklu silnika wypadaja rozne cylindry
        m.add("movb RL4,"+ANZTI);
        m.add("jnb r4.2,@M_MB");
        m.add("mov r6,#"+cw(C_MA));
        m.add("jmpr cc_UC,@M_MADD");
        m.add("M_MB:");
        m.add("mov r6,#"+cw(C_MB));
        m.add("M_MADD:");
        m.add("add r6,r5");
        m.add("movb RL4,[r6]");
        m.add("jmpr cc_UC,@M_ROUTE");
        // ---- NLS ----
        m.add("M_NLS:");
        m.add("movb RL5,#0x0");
        m.add("movb "+V_LCSTG+",RL5");
        m.add("mov r6,"+cw(C_EN));
        m.add("jnb r6.1,@M_RET");
        m.add("mov r5,"+V_NLSC);
        m.add("mov r6,"+cw(C_NDUR));
        m.add("cmp r5,r6");
        m.add("jmpr cc_NC,@M_RET");
        m.add("movb RL5,"+RL_B);
        m.add("mov r6,"+cw(C_NRL));
        m.add("cmpb RL5,RL6");
        m.add("jmpr cc_ULE,@M_RET");
        m.add("mov r5,"+V_NLSC);
        m.add("add r5,#0x1");
        m.add("mov "+V_NLSC+",r5");
        m.add("movb RL4,"+cw(C_NMK));
        m.add("jmpr cc_UC,@M_ROUTE");
        // Router strategii siedzi teraz w OSOBNYM stubie, wolanym stad i z
        // rolling LC. Dwa powody: nie duplikuje logiki, a przy okazji stub maski
        // skrocil sie o ~44 B, dzieki czemu skoki wewnetrzne znow miesza sie
        // w zasiegu rel8 (+-254 B) po dolozeniu rolling LC.
        m.add("M_ROUTE:");
        m.add("calls 0x"+Long.toHexString(S_ROU));
        m.add("M_RET:");
        m.add("pop r6"); m.add("rets");
        return m;
    }

    List<String> tiStub(int k){
        List<String> q=new ArrayList<String>();
        q.add("push r4"); q.add("push r5");
        q.add("calls 0x"+Long.toHexString(S_CM));
        q.add("jb r4."+k+",@C_CUT");
        q.add("pop r5"); q.add("pop r4");
        q.add("mov r1,"+TI_VAR[k]); q.add("rets");
        q.add("C_CUT:"); q.add("pop r5"); q.add("pop r4");
        q.add("mov r1,#0x0"); q.add("rets");
        return q;
    }

    /**
     * Selektor bankow: sprzeglo + tip dzwigni tempomatu, sygnalizacja lampka MIL.
     *
     *   sprzeglo wcisniete + tip PRZYSPIESZ  -> bank w gore  (0->1->2, klamruje na 2)
     *   sprzeglo wcisniete + tip ZWOLNIJ     -> bank w dol    (2->1->0, klamruje na 0)
     *   po kazdej zmianie: lampka mruga (numer banku + 1) razy
     *
     * Przelaczamy na ZBOCZU wcisniecia, nie na stanie - trzymanie przycisku daje
     * dokladnie jedna zmiane. Stan poprzedni pamieta V_PREVB: bit0 = tip+, bit1 = tip-.
     * V_PREVB jest odswiezany takze wtedy, gdy warunki NIE sa spelnione, zeby puszczenie
     * sprzegla z wcisnietym przyciskiem nie wygenerowalo fałszywego zbocza.
     */
    List<String> selStub(){
        List<String> s=new ArrayList<String>();
        s.add("calls 0x"+Long.toHexString(ORIG_SEL));
        s.add("push r4"); s.add("push r5"); s.add("push r6");
        s.add("movb RL4,#0x0"); s.add("movb "+V_MILON+",RL4");
        s.add("mov r6,"+cw(C_EN));
        // Skoki warunkowe C166 to rel8 liczone w SLOWACH, czyli zasieg +-254 B.
        // Stub jest dluzszy, wiec kazde wyjscie konczy sie wlasnym pop/rets zamiast
        // skakac na jeden wspolny koniec - inaczej asembler wywala "failed backfill".
        s.add("jb r6.2,@S_GO");
        s.add("pop r6"); s.add("pop r5"); s.add("pop r4"); s.add("rets");
        s.add("S_GO:");

        // --- sanityzacja smieci w XRAM po zalaczeniu zasilania ---
        s.add("movb RL4,"+V_BLPH);
        s.add("cmpb RL4,#0x4");
        s.add("jmpr cc_C,@S_OKPH");
        s.add("movb RL4,#0x0"); s.add("movb "+V_BLPH+",RL4");
        s.add("mov r5,#0x0");   s.add("mov "+V_BLTM+",r5");
        s.add("S_OKPH:");
        s.add("movb RL4,"+V_BANK);
        s.add("cmpb RL4,#0x3");
        s.add("jmpr cc_C,@S_OKBK");
        s.add("movb RL4,#0x0"); s.add("movb "+V_BANK+",RL4");
        s.add("S_OKBK:");
        // V_STRAT musi byc 1..3; smiec po zalaczeniu zasilania ma wyjsc na 1,
        // czyli na zachowanie sprzed tej zmiany - ciecie wtrysku.
        s.add("movb RL4,"+V_STRAT);
        s.add("cmpb RL4,#0x1");
        s.add("jmpr cc_C,@S_BADST");
        s.add("cmpb RL4,#0x4");
        s.add("jmpr cc_C,@S_OKST");
        s.add("S_BADST:");
        s.add("movb RL4,#0x1"); s.add("movb "+V_STRAT+",RL4");
        s.add("S_OKST:");

        // --- generator mrugania: V_BLPH = ile mrugniec zostalo, V_BLTM = faza ---
        s.add("movb RL4,"+V_BLPH);
        s.add("cmpb RL4,#0x0");
        s.add("jmpr cc_EQ,@S_SEL");
        s.add("mov r5,"+V_BLTM);
        s.add("add r5,#0x1");
        s.add("mov "+V_BLTM+",r5");
        s.add("mov r6,"+cw(C_MON));
        s.add("cmp r5,r6");
        s.add("jmpr cc_NC,@S_MOFF");
        s.add("movb RL4,#0x1"); s.add("movb "+V_MILON+",RL4");
        s.add("jmpr cc_UC,@S_SEL");
        s.add("S_MOFF:");
        s.add("mov r6,"+cw(C_MPER));
        s.add("cmp r5,r6");
        s.add("jmpr cc_C,@S_SEL");
        s.add("mov r5,#0x0"); s.add("mov "+V_BLTM+",r5");
        s.add("movb RL4,"+V_BLPH);
        s.add("subb RL4,#0x1");
        s.add("movb "+V_BLPH+",RL4");

        // --- warunki, w ktorych w ogole wolno przelaczac ---
        s.add("S_SEL:");
        s.add("mov r6,"+cw(C_SOPT));
        s.add("jnb r6.0,@S_NOCL");
        s.add("jnb "+KUPPL_R+"."+KUPPL_B+",@S_RST");
        s.add("S_NOCL:");
        s.add("mov r6,"+cw(C_SOPT));
        s.add("jnb r6.1,@S_NOFGR");
        s.add("movb RL5,"+FGRREG);
        s.add("jb r5.0,@S_RST");
        s.add("S_NOFGR:");
        s.add("mov r6,"+cw(C_SOPT));
        s.add("jb r6.2,@S_NOSPD");
        s.add("movb RL4,"+VFZG_B);
        s.add("cmpb RL4,#0x0");
        s.add("jmpr cc_NE,@S_RST");
        s.add("mov r5,"+NMOT_W);
        s.add("mov r6,"+cw(C_IDLE));
        s.add("cmp r5,r6");
        s.add("jmpr cc_UGT,@S_RST");
        s.add("S_NOSPD:");

        // --- przyciski dzwigni: r5 = bajt stanu, r6 = stan poprzedni ---
        s.add("movb RL5,"+FGRBTN);
        s.add("movb RH5,#0x0");
        s.add("movb RL6,"+V_PREVB);
        s.add("movb RH6,#0x0");
        // tip PRZYSPIESZ
        s.add("mov r4,"+cw(C_MUP));
        s.add("and r4,r5");
        s.add("jmpr cc_EQ,@S_DNT");
        s.add("jb r6.0,@S_DNT");
        // hamulec trzymany = modyfikator STRATEGII, inaczej modyfikator BANKU
        s.add("jb "+BREMS_R+"."+BREMS_B+",@S_SUP");
        s.add("movb RL4,"+V_BANK);
        s.add("addb RL4,#0x1");
        s.add("cmpb RL4,#0x3");
        s.add("jmpr cc_C,@S_UPOK");
        s.add("movb RL4,#0x2");
        s.add("S_UPOK:");
        s.add("movb "+V_BANK+",RL4");
        s.add("jmpr cc_UC,@S_SIG");
        s.add("S_SUP:");
        s.add("movb RL4,"+V_STRAT);
        s.add("addb RL4,#0x1");
        s.add("cmpb RL4,#0x4");
        s.add("jmpr cc_C,@S_SUOK");
        s.add("movb RL4,#0x3");
        s.add("S_SUOK:");
        s.add("movb "+V_STRAT+",RL4");
        s.add("jmpr cc_UC,@S_SIGS");
        // tip ZWOLNIJ
        s.add("S_DNT:");
        s.add("mov r4,"+cw(C_MDN));
        s.add("and r4,r5");
        s.add("jmpr cc_EQ,@S_SAVE");
        s.add("jb r6.1,@S_SAVE");
        s.add("jb "+BREMS_R+"."+BREMS_B+",@S_SDN");
        s.add("movb RL4,"+V_BANK);
        s.add("cmpb RL4,#0x0");
        s.add("jmpr cc_EQ,@S_SIG");
        s.add("subb RL4,#0x1");
        s.add("movb "+V_BANK+",RL4");
        s.add("jmpr cc_UC,@S_SIG");
        s.add("S_SDN:");
        s.add("movb RL4,"+V_STRAT);
        s.add("cmpb RL4,#0x2");
        s.add("jmpr cc_C,@S_SIGS");
        s.add("subb RL4,#0x1");
        s.add("movb "+V_STRAT+",RL4");
        // sygnalizacja strategii: tyle mrugniec, ktory to numer (1..3)
        s.add("S_SIGS:");
        s.add("movb RL4,"+V_STRAT);
        s.add("movb "+V_BLPH+",RL4");
        s.add("mov r4,#0x0"); s.add("mov "+V_BLTM+",r4");
        s.add("jmpr cc_UC,@S_SAVE");
        // wystartuj sygnalizacje: (numer banku + 1) mrugniec.
        // UWAGA na rejestry: r5 MUSI przezyc do S_SAVE, bo tam odtwarzam z niego
        // stan przyciskow. Dlatego zeruje V_BLTM przez r4, nie przez r5.
        s.add("S_SIG:");
        s.add("movb RL4,"+V_BANK);
        s.add("addb RL4,#0x1");
        s.add("movb "+V_BLPH+",RL4");
        s.add("mov r4,#0x0"); s.add("mov "+V_BLTM+",r4");
        // Stan poprzedni odtwarzam ZAWSZE z biezacego bajtu przyciskow (r5), a nie
        // z podkrecanych po drodze bitow r6. Inaczej sciezka "+" wychodzila stad
        // nie ruszywszy bitu 1 i pierwsze nastepne "-" bylo polykane jako brak zbocza.
        s.add("S_SAVE:");
        s.add("mov r6,#0x0");
        s.add("mov r4,"+cw(C_MUP));
        s.add("and r4,r5");
        s.add("jmpr cc_EQ,@S_V1");
        s.add("or r6,#0x1");
        s.add("S_V1:");
        s.add("mov r4,"+cw(C_MDN));
        s.add("and r4,r5");
        s.add("jmpr cc_EQ,@S_V2");
        s.add("or r6,#0x2");
        s.add("S_V2:");
        s.add("movb "+V_PREVB+",RL6");
        s.add("pop r6"); s.add("pop r5"); s.add("pop r4"); s.add("rets");

        // --- warunki niespelnione: tylko przepisz stan przyciskow ---
        s.add("S_RST:");
        s.add("movb RL5,"+FGRBTN);
        s.add("movb RH5,#0x0");
        s.add("jmpr cc_UC,@S_SAVE");
        return s;
    }

    /**
     * Router strategii ciecia. Wejscie: RL4 = maska LOGICZNA (bity w kolejnosci
     * hakow ti). Wyjscie: RL4 = maska PALIWA, V_AZMSK = maska ZAPLONU.
     * Wolany z dwoch miejsc - stub maski (LC/NLS) i rolling LC - zeby ta sama
     * decyzja nie byla napisana dwa razy.
     */
    List<String> routeStub(){
        List<String> q=new ArrayList<String>();
        q.add("push r5"); q.add("push r6");
        q.add("mov r6,"+cw(C_EN));
        q.add("jnb r6.5,@T_END");          // strategie wylaczone -> ciecie paliwa
        q.add("movb RL5,"+V_STRAT);
        q.add("cmpb RL5,#0x2");
        q.add("jmpr cc_C,@T_END");         // strategia 1 -> bez zmian
        q.add("cmpb RL5,#0x3");
        q.add("jmpr cc_EQ,@T_ALL");
        // strategia 2: maska idzie na zaplon, po odwroceniu bitow
        q.add("movb RH4,#0x0");
        q.add("mov r6,#"+O_REVT);
        q.add("add r6,r4");
        q.add("movb RL5,[r6]");
        q.add("movb "+V_AZMSK+",RL5");
        q.add("movb RL4,#0x0");
        q.add("jmpr cc_UC,@T_END");
        // strategia 3: zaplon ciety na wszystkich wg CAL
        q.add("T_ALL:");
        q.add("movb RL5,"+cw(C_AZALL));
        q.add("movb "+V_AZMSK+",RL5");
        q.add("movb RL4,#0x0");
        q.add("T_END:");
        q.add("pop r6"); q.add("pop r5"); q.add("rets");
        return q;
    }

    /**
     * ROLLING LAUNCH CONTROL. Wolany ze stuba maski, gdy sprzeglo jest PUSZCZONE.
     *
     * Warunki, wszystkie sprawdzane w KAZDYM przebiegu - zadnego zatrzasku:
     *   ENABLE bit6, przycisk CANCEL trzymany (B_fgrat), predkosc >= RLC SPEED_MIN.
     * Puszczenie przycisku albo zgubiony bit = natychmiastowy koniec ciecia.
     * Awaria odczytu daje BRAK ciecia, a nie ciecie w rozpedzie - to jest wazne,
     * bo tniemy tu pod obciazeniem, z kolami wpietymi w silnik.
     *
     * Drabinka jest wlasna (RLC TH/ZW/MASKA), niezalezna od LC. Powyzej progu 4
     * stopien 4 zostaje, wiec obroty stoja na gornej granicy okna jak na
     * ograniczniku - i o to chodzi w rolling launchu.
     */
    List<String> rlcStub(){
        List<String> q=new ArrayList<String>();
        q.add("push r5"); q.add("push r6");
        q.add("movb RL4,#0x0");
        q.add("mov r6,"+cw(C_EN));
        q.add("jnb r6.6,@L_END");
        // przycisk CANCEL trzymany?
        q.add("movb RL5,"+FGRBTN);
        q.add("movb RH5,#0x0");
        q.add("mov r6,"+cw(C_RBTN));
        q.add("and r6,r5");
        q.add("jmpr cc_EQ,@L_END");
        // predkosc - zeby nie dalo sie tego odpalic na postoju ani na luzie
        q.add("movb RL5,"+VFZG_B);
        q.add("mov r6,"+cw(C_RSPD));
        q.add("cmpb RL5,RL6");
        q.add("jmpr cc_C,@L_END");
        // drabinka od gory: pierwszy prog, ktory obroty przekroczyly, wygrywa
        q.add("mov r5,"+NMOT_W);
        q.add("mov r6,"+cw(C_RTH+3)); q.add("cmp r5,r6"); q.add("jmpr cc_NC,@L_S4");
        q.add("mov r6,"+cw(C_RTH+2)); q.add("cmp r5,r6"); q.add("jmpr cc_NC,@L_S3");
        q.add("mov r6,"+cw(C_RTH+1)); q.add("cmp r5,r6"); q.add("jmpr cc_NC,@L_S2");
        q.add("mov r6,"+cw(C_RTH));   q.add("cmp r5,r6"); q.add("jmpr cc_NC,@L_S1");
        q.add("jmpr cc_UC,@L_END");   // ponizej okna - silnik ma ciagnac
        q.add("L_S4:"); q.add("movb RL5,#0x4"); q.add("jmpr cc_UC,@L_STG");
        q.add("L_S3:"); q.add("movb RL5,#0x3"); q.add("jmpr cc_UC,@L_STG");
        q.add("L_S2:"); q.add("movb RL5,#0x2"); q.add("jmpr cc_UC,@L_STG");
        q.add("L_S1:"); q.add("movb RL5,#0x1");
        q.add("L_STG:");
        q.add("movb "+V_RSTG+",RL5");     // stub kata czyta to i dobiera kat
        q.add("subb RL5,#0x1");
        q.add("movb RH5,#0x0");
        q.add("shl r5,#0x1");
        q.add("movb RL4,"+ANZTI);
        q.add("jnb r4.2,@L_MB");
        q.add("mov r6,#"+cw(C_RMA));
        q.add("jmpr cc_UC,@L_MADD");
        q.add("L_MB:");
        q.add("mov r6,#"+cw(C_RMB));
        q.add("L_MADD:");
        q.add("add r6,r5");
        q.add("movb RL4,[r6]");
        q.add("calls 0x"+Long.toHexString(S_ROU));   // paliwo czy iskra - decyduje router
        q.add("pop r6"); q.add("pop r5"); q.add("rets");
        q.add("L_END:");
        q.add("movb RL4,#0x0");
        q.add("pop r6"); q.add("pop r5"); q.add("rets");
        return q;
    }

    /**
     * Hak maski zaplonu. Wchodzi w punkt zejscia 0x0C549E, juz po tym jak seryjny
     * kod ustawil azoffmsk_w. Dokladamy nasze bity operacja OR, wiec zadne zadanie
     * sterownika (diagnostyka, ochrona) nie ginie. Przy wylaczonym bicie 5 ENABLE
     * albo zerowej masce nie ruszamy nic.
     *
     * Oryginalna instrukcja (bmov 0xfda8.3,0xfd34.8) NIE jest tu asemblowana -
     * wklejam jej cztery surowe bajty przed tym kodem, zeby nie zalezec od tego,
     * czy asembler Ghidry przyjmie akurat te skladnie.
     */
    List<String> azStub(){
        List<String> q=new ArrayList<String>();
        q.add("push r4");
        q.add("mov r4,"+cw(C_EN));
        q.add("jnb r4.5,@A_END");
        q.add("movb RL4,"+V_AZMSK);
        q.add("cmpb RL4,#0x0");
        q.add("jmpr cc_EQ,@A_END");
        q.add("movb RH4,#0x0");
        q.add("or "+AZOFF+",r4");
        q.add("A_END:");
        q.add("pop r4");
        q.add("rets");
        return q;
    }

    /**
     * Hak lampki MIL. Wchodzi zaraz po tym, jak seryjny kod ustawil albo zgasil
     * B_mil (0xFD2A.7), i tylko DOKLADA nasze zapalenie. Nigdy nie gasi - jesli
     * sterownik ma realny blad, lampka pali sie na stale i nasza sygnalizacja
     * po prostu nie jest widoczna. To jest celowe: diagnostyka wazniejsza.
     */
    List<String> milStub(){
        List<String> q=new ArrayList<String>();
        q.add("push r4");
        q.add("mov r4,"+cw(C_EN));
        q.add("jnb r4.2,@M_ORIG");
        q.add("movb RL4,"+V_MILON);
        q.add("cmpb RL4,#0x0");
        q.add("jmpr cc_EQ,@M_ORIG");
        q.add("bset 0xfd2a.7");
        q.add("M_ORIG:");
        q.add("pop r4");
        q.add("movb RL4,0x91e9");   // instrukcja wyjeta hakiem
        q.add("rets");
        return q;
    }

    /** wspolny szkielet: indeks banku (albo 0 gdy multimapa wylaczona) -> r7 */
    void bankIdx(List<String> q,String lblBank,String lblIdx){
        q.add("mov r6,"+cw(C_EN));
        q.add("jb r6.3,@"+lblBank);
        q.add("mov r7,#0x0");
        q.add("jmpr cc_UC,@"+lblIdx);
        q.add(lblBank+":");
        q.add("movb RL7,"+V_BANK);
        q.add("movb RH7,#0x0");
        q.add(lblIdx+":");
    }

    List<String> ptrStub(String tbl,String dst,boolean unused){
        List<String> q=new ArrayList<String>();
        q.add("push r6"); q.add("push r7");
        bankIdx(q,"Z_BANK","Z_IDX");
        q.add("shl r7,#0x1");
        q.add("mov r6,#"+tbl);
        q.add("add r6,r7");
        q.add("mov "+dst+",[r6]");
        q.add("pop r7"); q.add("pop r6"); q.add("rets");
        return q;
    }

    List<String> lbStub(){
        List<String> q=new ArrayList<String>();
        q.add("push r6"); q.add("push r7");
        bankIdx(q,"L_BANK","L_IDX");
        // offset w stronie
        q.add("mov r6,r7");
        q.add("shl r6,#0x1");
        q.add("add r6,#"+O_LBOFFT);
        q.add("mov r12,[r6]");
        // numer strony (r13 nie ma nazw bajtowych, wiec przez r7)
        q.add("mov r6,#"+O_LBPGT);
        q.add("add r6,r7");
        q.add("movb RL7,[r6]");
        q.add("movb RH7,#0x0");
        q.add("mov r13,r7");
        q.add("pop r7"); q.add("pop r6"); q.add("rets");
        return q;
    }

    /** Zastepuje "mov r4,#0x1D04" - wskaznik danych KFRLSNT. Strona (r5) zostaje
     *  bez zmian, bo kopie lezą na tej samej stronie 0x2F. */
    List<String> rsStub(){
        List<String> q=new ArrayList<String>();
        q.add("push r6"); q.add("push r7");
        q.add("mov r6,"+cw(C_EN));
        q.add("jb r6.4,@R_GEAR");
        // stara sciezka: sufit po banku
        bankIdx(q,"R_BANK","R_IDX");
        q.add("shl r7,#0x1");
        q.add("mov r6,#"+O_RST);
        q.add("add r6,r7");
        q.add("mov r4,[r6]");
        q.add("pop r7"); q.add("pop r6"); q.add("rets");
        // sufit po biegu: gangi 1..6 -> tablice 0..5, wszystko inne -> tablica 1 biegu
        q.add("R_GEAR:");
        q.add("movb RL7,"+GANGI);
        q.add("movb RH7,#0x0");
        q.add("cmpb RL7,#0x1");
        q.add("jmpr cc_C,@R_GBAD");
        q.add("cmpb RL7,#0x7");
        q.add("jmpr cc_C,@R_GOK");
        q.add("R_GBAD:");
        q.add("mov r7,#0x1");
        q.add("R_GOK:");
        q.add("sub r7,#0x1");
        q.add("shl r7,#0x1");
        q.add("mov r6,#"+O_GEART);
        q.add("add r6,r7");
        q.add("mov r4,[r6]");
        q.add("pop r7"); q.add("pop r6"); q.add("rets");
        return q;
    }

    // ======================= MAPPACK =======================
    // Format pod a2lgen.py: konwerter rozpoznaje kolumny po nazwach naglowka
    // i czyta GEOMETRIE z "Kolumny"/"Wiersze"/"Ilosc". Poprzednia wersja tych
    // kolumn nie miala, wiec kazda mapa wchodzila jako skalar 1x1.
    // Kolumna wartosci musi nazywac sie tak, zeby NIE zlapala wzorca 'comment'
    // (wzorzec obejmuje m.in. "znaczenie.*") - inaczej podbiera role "Opis".
    // Kolumny bazowe MUSZA byc przed osiowymi: a2lgen dopasowuje pola po kolei,
    // a wzorzec "Factor" lapie tez "axis_x.factor" - wygrywa kolumna o nizszym indeksie.
    // KONWENCJA ADRESOW W MAPPACKU.
    // true  = OFFSET W PLIKU (adres chipowy - 0x10000). Tak adresuje WinOLS, gdy
    //         otwierasz surowy bin i wpisujesz "Start address" z reki.
    // false = adres CHIPOWY, jak w oryginalnym A2L ($B1C3C). Wtedy przy imporcie
    //         MUSISZ ustawic offset 0x10000, inaczej wszystko wyjdzie 64 kB za wysoko
    //         i zobaczysz smieci albo same 0xFF.
    static final boolean MP_FILE_OFFSET = true;

    static final String[] MP_HEAD = { "Nazwa","Adres","Folder","Typ","Znak",
        "Kolumny","Wiersze","Ilosc","Factor","Offset","Jednostka","Opis","Wartosc_teraz",
        "axis_x.addr","axis_x.name","axis_x.datatype","axis_x.bsigned","axis_x.factor",
        "axis_x.offset","axis_x.unit",
        "axis_y.addr","axis_y.name","axis_y.datatype","axis_y.bsigned","axis_y.factor",
        "axis_y.offset","axis_y.unit","msb" };

    // KOLEJNOSC BAJTOW. C166 jest little-endian (Intel / LoHi): slowo 0x0360
    // lezy w pliku jako 60 03. Kazda wartosc 16-bitowa - osie nmot i rl oraz
    // dane KFRLSNT - MUSI byc czytana LSB_FIRST. a2lgen ma domyslnie
    // MSB_FIRST=wlaczone, wiec albo odznacz ten checkbox, albo uzyj gotowego
    // A2L, ktory juz ma "BYTE_ORDER LSB_FIRST" w MOD_COMMON.
    // Mapy 8-bitowe (KFZW i8, KFLBTS u8) sa na to odporne - dlatego wygladaly
    // dobrze, kiedy osie i sufit napelnienia pokazywaly smieci.
    static final String MP_MSB = "0";

    // OSIE I GEOMETRIA WPROST Z A2L (Z20LER 0261208153 / 1037374301 ME7.6.2).
    // Wszystkie te mapy maja FNC_VALUES ... COLUMN_DIR, czyli w pamieci szybciej
    // zmienia sie os Y z A2L. Dlatego "kolumny" w mappacku to os Y z A2L, a nie X.
    // Przeliczniki policzone z COEFFS metod compu, nie zgadywane:
    //   zw_sb_q0p75    -> 0.75      st        (255/191.25)
    //   fak_ub_b2      -> 0.0078125 lambda    (256/2)
    //   rel_uw_q0p0234 -> 0.0234375 %         (32/0.75)
    //   nmot_uw_q0p25  -> 0.25      obr/min
    //   nmot_ub_q40    -> 40        obr/min
    //   rel_ub_q0p75   -> 0.75      %
    //   temp_ub_q0p75_o48 -> 0.75, offset -48, C
    // Adresy osi to WARTOSCI, czyli rekord AXIS_PTS + licznik. Wszystkie cztery
    // rekordy sprawdzone w tym pliku: liczniki 16/12/16/12 sie zgadzaja.
    static final String[] AX_ZW_X  = {"0B2B46","rl",  "u16","0","0.0234375","0","%"};       // SRL12ZUUW
    static final String[] AX_ZW_Y  = {"0B2B0A","nmot","u16","0","0.25",     "0","obr/min"}; // SNM16ZUUW
    static final String[] AX_LB_X  = {"0B806C","nmot","u8", "0","40",       "0","obr/min"}; // SNM16GKUB
    static final String[] AX_LB_Y  = {"0B80A8","rl",  "u8", "0","0.75",     "0","%"};       // SRL12GKUB
    static final String[] AX_RSN_X = {"0BDCE4","nmot","u16","0","0.25",     "0","obr/min"};
    static final String[] AX_RSN_Y = {"0BDCDC","tumg","u8", "0","0.75",   "-48","C"};
    static final String[] AX_NONE  = {"","","","","","",""};

    // mapy 2D: nazwa, adres, kolumny, wiersze, typ, znak, factor, jednostka, opis
    static final Object[][] MP_MAPS = {
      {"KFZW bank0 (seryjna)", Long.valueOf(MAP_ZW), Integer.valueOf(12), Integer.valueOf(16),
       "i8","1","0.75","st","Zuendwinkelkennfeld (KFZW) - bank 0, oryginalna komorka. Zrodlo: A2L 1037374301", AX_ZW_X, AX_ZW_Y},
      {"KFZW bank1",           Long.valueOf(ZW_B1),  Integer.valueOf(12), Integer.valueOf(16),
       "i8","1","0.75","st","Zuendwinkelkennfeld (KFZW) - bank 1", AX_ZW_X, AX_ZW_Y},
      {"KFZW bank2",           Long.valueOf(ZW_B2),  Integer.valueOf(12), Integer.valueOf(16),
       "i8","1","0.75","st","Zuendwinkelkennfeld (KFZW) - bank 2", AX_ZW_X, AX_ZW_Y},
      {"KFLBTS bank0 (seryjna)",Long.valueOf(MAP_LB),Integer.valueOf(16), Integer.valueOf(12),
       "u8","0","0.0078125","lambda","Lambdasoll fuer Bauteileschutz (KFLBTS) - bank 0, oryginalna komorka. To mapa WZBOGACANIA pod obciazeniem, nie ogolny cel lambdy", AX_LB_X, AX_LB_Y},
      {"KFLBTS bank1",         Long.valueOf(LB_B1),  Integer.valueOf(16), Integer.valueOf(12),
       "u8","0","0.0078125","lambda","Lambdasoll fuer Bauteileschutz (KFLBTS) - bank 1", AX_LB_X, AX_LB_Y},
      {"KFLBTS bank2",         Long.valueOf(LB_B2),  Integer.valueOf(16), Integer.valueOf(12),
       "u8","0","0.0078125","lambda","Lambdasoll fuer Bauteileschutz (KFLBTS) - bank 2", AX_LB_X, AX_LB_Y},
      {"KFRLSNT bank0 (seryjna)",Long.valueOf(RS_SRC),Integer.valueOf(16), Integer.valueOf(8),
       "u16","0","0.0234375","%","SUFIT napelnienia dla maks. momentu, bank 0 - oryginalna komorka. "
       +"Kolumny = obroty 1520..6500, wiersze = temp. otoczenia -20..40 C. To ZABEZPIECZENIE: "
       +"wiersze dla 35 i 40 C sa nizej celowo, chronia przed detonacja przy goracym powietrzu",
       AX_RSN_X, AX_RSN_Y},
      {"KFRLSNT bank1",        Long.valueOf(RS_B1),  Integer.valueOf(16), Integer.valueOf(8),
       "u16","0","0.0234375","%","SUFIT napelnienia, bank 1", AX_RSN_X, AX_RSN_Y},
      {"KFRLSNT bank2",        Long.valueOf(RS_B2),  Integer.valueOf(16), Integer.valueOf(8),
       "u16","0","0.0234375","%","SUFIT napelnienia, bank 2", AX_RSN_X, AX_RSN_Y},
      {"KFRLSNT bieg 1",       Long.valueOf(RG_BASE),            Integer.valueOf(16), Integer.valueOf(8),
       "u16","0","0.0234375","%","SUFIT napelnienia na 1 biegu. Uzywany takze gdy bieg jest NIEROZPOZNANY "
       +"(ponizej 1400 obr/min) i na wstecznym - trzymaj go najbardziej zachowawczo", AX_RSN_X, AX_RSN_Y},
      {"KFRLSNT bieg 2",       Long.valueOf(RG_BASE+256L),       Integer.valueOf(16), Integer.valueOf(8),
       "u16","0","0.0234375","%","SUFIT napelnienia na 2 biegu", AX_RSN_X, AX_RSN_Y},
      {"KFRLSNT bieg 3",       Long.valueOf(RG_BASE+512L),       Integer.valueOf(16), Integer.valueOf(8),
       "u16","0","0.0234375","%","SUFIT napelnienia na 3 biegu", AX_RSN_X, AX_RSN_Y},
      {"KFRLSNT bieg 4",       Long.valueOf(RG_BASE+768L),       Integer.valueOf(16), Integer.valueOf(8),
       "u16","0","0.0234375","%","SUFIT napelnienia na 4 biegu", AX_RSN_X, AX_RSN_Y},
      {"KFRLSNT bieg 5",       Long.valueOf(RG_BASE+1024L),      Integer.valueOf(16), Integer.valueOf(8),
       "u16","0","0.0234375","%","SUFIT napelnienia na 5 biegu", AX_RSN_X, AX_RSN_Y},
      {"KFRLSNT bieg 6",       Long.valueOf(RG_BASE+1280L),      Integer.valueOf(16), Integer.valueOf(8),
       "u16","0","0.0234375","%","SUFIT napelnienia na 6 biegu", AX_RSN_X, AX_RSN_Y},
    };
    // tablice 3-elementowe: nazwa, adres, ilosc, typ, factor, jednostka, opis
    static final Object[][] MP_ARRS = {
      {"MM wskaznik KFZW", Long.valueOf(T_ZW),   Integer.valueOf(3),"u16","1","-",
       "wskaznik mapy zaplonu dla banku 0/1/2 (postac DPP-relatywna)"},
      {"MM offset KFLBTS", Long.valueOf(T_LBOFF),Integer.valueOf(3),"u16","1","-",
       "offset mapy lambdy w stronie, dla banku 0/1/2"},
      {"MM strona KFLBTS", Long.valueOf(T_LBPG), Integer.valueOf(3),"u8","1","-",
       "numer strony mapy lambdy, dla banku 0/1/2"},
      {"MM offset KFRLSNT",Long.valueOf(T_RS),  Integer.valueOf(3),"u16","1","-",
       "offset danych sufitu napelnienia w stronie 0x2F, dla banku 0/1/2"},
      {"MM offset KFRLSNT/bieg",Long.valueOf(T_GEAR),Integer.valueOf(6),"u16","1","-",
       "offset sufitu napelnienia w stronie 0x2F, dla biegu 1..6 (ENABLE bit4)"},
      {"MM odwracanie maski",  Long.valueOf(T_REV), Integer.valueOf(16),"u8","1","-",
       "maska paliwa -> maska zaplonu. Bity ti ida 01,02,04,08 w kolejnosci zaplonu, "
       +"a tablica zaplonu pod 0x0B679E ma 08,04,02,01 - czyli odwrotnie"},
    };

    void writeMappack(File f, byte[] ch, String vin) throws Exception {
        PrintWriter w = new PrintWriter(f, "UTF-8");
        StringBuilder h = new StringBuilder();
        for (int i = 0; i < MP_HEAD.length; i++) {
            if (i > 0) h.append(';');
            h.append('"').append(MP_HEAD[i]).append('"'); }
        w.println(h.toString());

        // ---- tablica CAL: skalary ----
        for (int i = 0; i < CAL_N; i++) {
            long a = calAddr(i);
            int raw = (ch[(int)(a-fbase)]&0xFF) | ((ch[(int)(a-fbase+1)]&0xFF)<<8);
            String t = CAL[i][2];
            String typ = t.equals("u16") ? "u16" : (t.equals("i8w") ? "i8" : "u8");
            String sgn = t.equals("i8w") ? "1" : "0";
            mpRow(w, CAL[i][0], a, CAL[i][1], typ, sgn, "", "", "",
                  CAL[i][3], CAL[i][4], CAL[i][6], String.format("%04X", raw));
        }
        // ---- tablice bankow ----
        for (Object[] r : MP_ARRS) {
            long a = ((Long)r[1]).longValue();
            int n = ((Integer)r[2]).intValue();
            boolean wide = "u16".equals(r[3]);
            StringBuilder v = new StringBuilder();
            for (int k = 0; k < n; k++) {
                if (k > 0) v.append(' ');
                int off = (int)(a-fbase) + k*(wide?2:1);
                v.append(wide ? String.format("%04X",(ch[off]&0xFF)|((ch[off+1]&0xFF)<<8))
                              : String.format("%02X", ch[off]&0xFF)); }
            mpRow(w, (String)r[0], a, "MultiMap", (String)r[3], "0",
                  "", "", String.valueOf(n), (String)r[4], (String)r[5], (String)r[6], v.toString());
        }
        // ---- mapy 2D ----
        for (Object[] r : MP_MAPS) {
            long a = ((Long)r[1]).longValue();
            int cols = ((Integer)r[2]).intValue(), rows = ((Integer)r[3]).intValue();
            mpRow(w, (String)r[0], a, "MultiMap", (String)r[4], (String)r[5],
                  String.valueOf(cols), String.valueOf(rows), "",
                  (String)r[6], (String)r[7], (String)r[8], (cols*rows)+" B",
                  (String[])r[9], (String[])r[10]);
        }
        // ---- haki: nie sa kalibracja, ale warto miec adresy pod reka ----
        long[] hs = { H_ANG, H_SEL, H_TI[0], H_TI[1], H_TI[2], H_TI[3], H_ZW, H_LB, H_RS, H_MIL, H_AZ };
        String[] hn = { "HOOK slot kat","HOOK slot selektor","HOOK ti cyl1","HOOK ti cyl3",
                        "HOOK ti cyl4","HOOK ti cyl2","HOOK wskaznik KFZW",
                        "HOOK wskaznik KFLBTS","HOOK wskaznik KFRLSNT","HOOK lampka MIL",
                        "HOOK maska zaplonu" };
        int[][] ho = { O_ANG, O_SEL, O_TI[0], O_TI[1], O_TI[2], O_TI[3], O_ZW, O_LB, O_RS, O_MIL, O_AZ };
        for (int i = 0; i < hs.length; i++) {
            StringBuilder cur = new StringBuilder(), org = new StringBuilder();
            for (int k = 0; k < 4; k++) cur.append(String.format("%02X ", ch[(int)(hs[i]-fbase+k)]&0xFF));
            for (int k = 0; k < 4; k++) org.append(String.format("%02X ", ho[i][k]));
            mpRow(w, hn[i], hs[i], "Hooks", "u8", "0", "", "", "4", "1", "-",
                  "seryjnie bylo: "+org.toString().trim()+". Wpisz te bajty, zeby wycofac ten hak",
                  cur.toString().trim());
        }
        w.close();
    }

    void mpRow(PrintWriter w, String nazwa, long chipAddr, String folder, String typ,
               String znak, String kol, String wier, String ilosc, String factor,
               String jedn, String opis, String wartosc) {
        mpRow(w, nazwa, chipAddr, folder, typ, znak, kol, wier, ilosc, factor,
              jedn, opis, wartosc, AX_NONE, AX_NONE);
    }

    /** adres chipowy -> taki, jakiego oczekuje mappack */
    String mpA(long chip){
        return String.format("%06X", MP_FILE_OFFSET ? (chip - fbase) : chip); }
    /** to samo dla adresu osi podanego jako tekst hex (chipowy) */
    String mpA(String hexChip){
        if(hexChip==null || hexChip.length()==0) return "";
        return mpA(Long.parseLong(hexChip, 16)); }

    /** jeden wiersz mappacku; kolejnosc pol musi odpowiadac MP_HEAD */
    void mpRow(PrintWriter w, String nazwa, long chipAddr, String folder, String typ,
               String znak, String kol, String wier, String ilosc, String factor,
               String jedn, String opis, String wartosc, String[] ax, String[] ay) {
        String[] c = { nazwa, mpA(chipAddr), folder, typ, znak,
                       kol, wier, ilosc, factor, "0", jedn, opis, wartosc,
                       mpA(ax[0]),ax[1],ax[2],ax[3],ax[4],ax[5],ax[6],
                       mpA(ay[0]),ay[1],ay[2],ay[3],ay[4],ay[5],ay[6], MP_MSB };
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < c.length; i++) {
            if (i > 0) sb.append(';');
            sb.append('"').append(q(c[i])).append('"'); }
        w.println(sb.toString());
    }

    static String q(String s){ return s==null?"":s.replace("\"","'"); }
    static String fmt(double d){
        if(d==Math.floor(d)&&!Double.isInfinite(d)) return String.valueOf((long)d);
        return String.format(Locale.US,"%.6f",d); }
}
