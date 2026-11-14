#!/usr/bin/env bash
#
# Meow Mod Analyzer — Linux / macOS port of MeowModAnalyzer.ps1
#
# Mirrors the five passes of the original PowerShell script:
#   1. SHA1 verification (Modrinth + Megabase)
#   2. Pattern / string / fullwidth-Unicode scan (incl. nested JARs)
#   3. Bypass / injection scan
#   4. Obfuscation analysis
#   5. JVM / runtime injection scan
#
# Dependencies: bash, unzip, perl, curl, awk, sed, find, sort,
#               plus sha1sum / shasum / openssl.

# ---------------------------------------------------------------------------
# Locale (UTF-8 for correct character lengths; binary scans force LC_ALL=C)
# ---------------------------------------------------------------------------
if locale -a 2>/dev/null | grep -qiE '^en_US\.utf-?8$'; then
    export LC_ALL=en_US.UTF-8
elif locale -a 2>/dev/null | grep -qiE '^(C\.utf-?8|C)$'; then
    export LC_ALL=C.UTF-8
fi

# ---------------------------------------------------------------------------
# Colors (PowerShell ConsoleColor -> ANSI)
# ---------------------------------------------------------------------------
ESC=$'\033'
C_RESET="${ESC}[0m"
C_BLACK="${ESC}[30m"
C_DARKRED="${ESC}[31m"
C_DARKGREEN="${ESC}[32m"
C_DARKYELLOW="${ESC}[33m"
C_DARKBLUE="${ESC}[34m"
C_DARKMAGENTA="${ESC}[35m"
C_DARKCYAN="${ESC}[36m"
C_GRAY="${ESC}[37m"
C_DARKGRAY="${ESC}[90m"
C_RED="${ESC}[91m"
C_GREEN="${ESC}[92m"
C_YELLOW="${ESC}[93m"
C_BLUE="${ESC}[94m"
C_MAGENTA="${ESC}[95m"
C_CYAN="${ESC}[96m"
C_WHITE="${ESC}[97m"
C_BG_DARKRED="${ESC}[41m"
C_BG_DARKYELLOW="${ESC}[43m"
C_BG_DARKMAGENTA="${ESC}[45m"
C_BG_YELLOW="${ESC}[103m"

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
missing=""
for cmd in unzip perl curl awk sed find sort grep; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        missing="$missing $cmd"
    fi
done

SHA1_TOOL=""
if command -v sha1sum >/dev/null 2>&1; then
    SHA1_TOOL="sha1sum"
elif command -v shasum >/dev/null 2>&1; then
    SHA1_TOOL="shasum"
elif command -v openssl >/dev/null 2>&1; then
    SHA1_TOOL="openssl"
fi

if [ -n "$missing" ] || [ -z "$SHA1_TOOL" ]; then
    printf '%s❌ Missing required dependencies:%s%s\n' "$C_RED" "$C_RESET" "$missing"
    [ -z "$SHA1_TOOL" ] && printf '%s   sha1sum / shasum / openssl%s\n' "$C_RED" "$C_RESET"
    exit 1
fi

if ! command -v pgrep >/dev/null 2>&1; then
    HAVE_PGREP=0
else
    HAVE_PGREP=1
fi

# ---------------------------------------------------------------------------
# Temp workspace
# ---------------------------------------------------------------------------
TMPROOT=$(mktemp -d "${TMPDIR:-/tmp}/meowmodanalyzer.XXXXXX") || {
    printf '%s❌ Could not create temporary directory%s\n' "$C_RED" "$C_RESET"
    exit 1
}
cleanup() {
    [ -n "$TMPROOT" ] && rm -rf "$TMPROOT" 2>/dev/null
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

SCAN_PL="$TMPROOT/scan.pl"
PATTERNS_FILE="$TMPROOT/patterns.txt"
CHEAT_FILE="$TMPROOT/cheat-strings.txt"
FW_POOL_FILE="$TMPROOT/fullwidth-pool.txt"

# ---------------------------------------------------------------------------
# Embedded scanner (Perl keeps byte-exact regex semantics of .NET on binaries)
# ---------------------------------------------------------------------------
cat > "$SCAN_PL" <<'PERL_HELPER'
use strict;
use warnings;

my $mode = shift @ARGV // '';

sub read_lines {
    my ($path) = @_;
    open(my $fh, '<', $path) or return ();
    my @out;
    while (my $line = <$fh>) {
        chomp $line;
        push @out, $line if length $line;
    }
    close $fh;
    return @out;
}

sub slurp {
    my ($path) = @_;
    open(my $fh, '<', $path) or return undef;
    binmode $fh;
    local $/;
    my $data = <$fh>;
    close $fh;
    return $data;
}

# U+FF10-FF19 / U+FF21-FF3A / U+FF41-FF5A encoded as UTF-8 bytes
sub fw_atom {
    return qr/(?:\xEF\xBC[\xA1-\xBA\x90-\x99]|\xEF\xBD[\x81-\x9A])/;
}

if ($mode eq 'patterns') {
    my ($content_file, $pattern_file) = @ARGV;
    my $data = slurp($content_file);
    exit 1 unless defined $data;
    my @patterns = read_lines($pattern_file);
    exit 0 unless @patterns;
    my $alt = join '|', @patterns;
    my $re = qr/(?<![A-Za-z])($alt)(?![A-Za-z])/;
    while ($data =~ /$re/g) {
        print "$1\n";
    }
}
elsif ($mode eq 'strings') {
    my ($content_file, $string_file) = @ARGV;
    my $data = slurp($content_file);
    exit 1 unless defined $data;
    for my $s (read_lines($string_file)) {
        print "$s\n" if index($data, $s) >= 0;
    }
}
elsif ($mode eq 'fullwidth') {
    my ($content_file) = @ARGV;
    my $data = slurp($content_file);
    exit 1 unless defined $data;
    my $atom = fw_atom();
    while ($data =~ /($atom+)/g) {
        print "$1\n";
    }
}
elsif ($mode eq 'resolve') {
    my ($found_file, $pool_file) = @ARGV;
    my @found = read_lines($found_file);
    my @pool  = read_lines($pool_file);

    my %seen;
    my @resolved;
    for my $fw (grep { !$seen{$_}++ } @found) {
        next if length($fw) < 9;    # < 3 fullwidth characters (3 bytes each)
        my $best;
        for my $cs (@pool) {
            if (index($cs, $fw) >= 0) {
                $best = $cs if !defined($best) || length($cs) < length($best);
            }
        }
        if (defined $best) {
            push @resolved, $best;
        }
        elsif (length($fw) >= 18) {  # >= 6 fullwidth characters
            push @resolved, $fw;
        }
    }

    my %seen2;
    @resolved = grep { !$seen2{$_}++ } @resolved;
    for my $fw (@resolved) {
        my $redundant = 0;
        for my $other (@resolved) {
            if (length($fw) < length($other) && index($other, $fw) >= 0) {
                $redundant = 1;
                last;
            }
        }
        print "$fw\n" unless $redundant;
    }
}
elsif ($mode eq 'obf') {
    my ($dir, $names_file) = @ARGV;
    my @names = grep { /\.class$/i } read_lines($names_file);

    my ($total, $numeric, $unicode, $fullwidth, $japanese) = (0, 0, 0, 0, 0);
    my ($single, $two, $gibberish, $novowel, $confusion, $singlepkg) = (0, 0, 0, 0, 0, 0);

    for my $name (@names) {
        $total++;
        my $class = (split m{/}, $name)[-1];
        $class =~ s/\.class$//i;

        $numeric++   if $class =~ /^[0-9]+$/;
        $unicode++   if $class =~ /[\x80-\xFF]/;
        $fullwidth++ if $class =~ /(?:\xEF\xBC[\xA1-\xBA\x90-\x99]|\xEF\xBD[\x81-\x9A])/;
        $japanese++  if $class =~ /(?:\xE3\x81[\x80-\x9F]|\xE3\x82[\xA0-\xBF])/;
        $single++    if $class =~ /^[a-zA-Z]$/;
        $two++       if $class =~ /^[a-zA-Z]{2}$/;
        $confusion++ if $class =~ /^[Il1O0]+$/ || $class =~ /^_+$/;

        if (length($class) >= 3 && length($class) <= 8 && $class =~ /^[a-zA-Z]+$/) {
            my $vowels = () = $class =~ /[aeiouAEIOU]/g;
            $novowel++ if $vowels == 0;
            my $cluster = $class =~ /[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]{3,}/;
            if ($cluster && ($vowels / length($class)) < 0.3) {
                $gibberish++;
            }
        }

        my @segs = split m{/}, $name;
        if (@segs > 1) {
            pop @segs;
            $singlepkg += scalar(grep { length($_) == 1 } @segs);
        }
    }

    # Content sample for obfuscator signatures / fullwidth strings
    my $sample = '';
    my $sample_size = 0;
    for my $name (@names) {
        last if $sample_size >= 150000;
        next if $name =~ m{(^|/)\.\.(/|$)};
        my $path = "$dir/$name";
        next unless -f $path;
        my $size = -s $path;
        next unless $size < 100000 && $size > 100;
        my $data = slurp($path);
        next unless defined $data;
        $sample .= $data;
        $sample_size += length($data);
    }

    my $atom = fw_atom();
    my $fwcount = () = $sample =~ /$atom+/g;
    my @fwex;
    while ($sample =~ /($atom+)/g) {
        push @fwex, $1;
        last if @fwex >= 3;
    }

    my @obfuscators = (
        ['Skidfuscator',   ['dev/skidfuscator', 'Skidfuscator', 'skidfuscator.dev']],
        ['Paramorphism',   ['Paramorphism', 'paramorphism-', 'dev/paramorphism']],
        ['Radon',          ['ItzSomebody/Radon', 'me/itzsomebody/radon', 'Radon Obfuscator']],
        ['Caesium',        ['sim0n/Caesium', 'Caesium Obfuscator', 'dev/sim0n/caesium']],
        ['Bozar',          ['vimasig/Bozar', 'Bozar Obfuscator', 'com/bozar']],
        ['Branchlock',     ['Branchlock', 'branchlock.dev']],
        ['Binscure',       ['Binscure', 'com/binscure']],
        ['SuperBlaubeere', ['superblaubeere', 'superblaubeere27']],
        ['Qprotect',       ['Qprotect', 'QProtect', 'mdma.dev/qprotect']],
        ['Zelix',          ['ZKMFLOW', 'ZKM', 'ZelixKlassMaster', 'com/zelix']],
        ['Stringer',       ['StringerJavaObfuscator', 'com/licel/stringer']],
        ['JNIC',           ['JNIC', 'jnic.obf', 'jnic-obfuscator']],
        ['Scuti',          ['ScutiObf', 'scuti.obf']],
        ['Smoke',          ['SmokeObf', 'smoke.obf']],
    );

    print "total=$total\n";
    print "numeric=$numeric\n";
    print "unicode=$unicode\n";
    print "fullwidth=$fullwidth\n";
    print "japanese=$japanese\n";
    print "single=$single\n";
    print "two=$two\n";
    print "gibberish=$gibberish\n";
    print "novowel=$novowel\n";
    print "confusion=$confusion\n";
    print "singlepkg=$singlepkg\n";
    print "fwcount=$fwcount\n";
    print "fwexamples=" . join(', ', @fwex) . "\n";

    for my $obf (@obfuscators) {
        my ($name, $pats) = @$obf;
        for my $pat (@$pats) {
            if (index($sample, $pat) >= 0) {
                print "obfmatch=$name\t$pat\n";
                last;
            }
        }
    }
}
elsif ($mode eq 'bypass') {
    my ($dir, $names_file) = @ARGV;
    my @names = grep { /\.class$/i } read_lines($names_file);

    my ($total, $numeric, $unicode, $obfuscated) = (0, 0, 0, 0);

    for my $name (@names) {
        $total++;
        my $class = (split m{/}, $name)[-1];
        $class =~ s/\.class$//i;

        $numeric++ if $class =~ /^[0-9]+$/;
        $unicode++ if $class =~ /[\x80-\xFF]/;

        my @segs = split m{/}, $name;
        $segs[-1] =~ s/\.class$//i if @segs;
        my ($run, $max) = (0, 0);
        for my $seg (@segs) {
            if (length($seg) == 1) {
                $run++;
                $max = $run if $run > $max;
            }
            else {
                $run = 0;
            }
        }
        $obfuscated++ if $max >= 3;
    }

    my ($runtime, $download, $exfil) = (0, 0, 0);
    if (-d $dir) {
        require File::Find;
        File::Find::find(
            sub {
                return unless -f $_;
                my $data = slurp($_);
                return unless defined $data;

                if (!$runtime
                    && index($data, 'java/lang/Runtime') >= 0
                    && index($data, 'getRuntime') >= 0
                    && index($data, 'exec') >= 0) {
                    $runtime = 1;
                }
                if (!$download
                    && index($data, 'openConnection') >= 0
                    && index($data, 'HttpURLConnection') >= 0
                    && index($data, 'FileOutputStream') >= 0) {
                    $download = 1;
                }
                if (!$exfil
                    && index($data, 'openConnection') >= 0
                    && index($data, 'setDoOutput') >= 0
                    && index($data, 'getOutputStream') >= 0
                    && index($data, 'getProperty') >= 0) {
                    $exfil = 1;
                }
            },
            $dir
        );
    }

    my $obfpct = $total >= 10 ? sprintf('%.0f', ($obfuscated / $total) * 100) : 0;
    my $numpct = $total >= 5  ? sprintf('%.0f', ($numeric    / $total) * 100) : 0;
    my $unipct = $total >= 5  ? sprintf('%.0f', ($unicode    / $total) * 100) : 0;

    print "total=$total\n";
    print "numeric=$numeric\n";
    print "unicode=$unicode\n";
    print "obfuscated=$obfuscated\n";
    print "obfpct=$obfpct\n";
    print "numpct=$numpct\n";
    print "unipct=$unipct\n";
    print "runtime=$runtime\n";
    print "download=$download\n";
    print "exfil=$exfil\n";
}
elsif ($mode eq 'jsonkey') {
    my $key = shift @ARGV // '';
    local $/;
    my $data = <STDIN>;
    $data = '' unless defined $data;
    if ($data =~ /"\Q$key\E"\s*:\s*"((?:[^"\\]|\\.)*)"/) {
        my $value = $1;
        $value =~ s/\\"/"/g;
        $value =~ s/\\\\/\\/g;
        $value =~ s/\\n/\n/g;
        $value =~ s/\\r/\r/g;
        $value =~ s/\\t/\t/g;
        $value =~ s/\\u([0-9a-fA-F]{4})/chr(hex($1))/ge;
        print $value;
    }
}
PERL_HELPER

# ---------------------------------------------------------------------------
# Cheat pattern / string databases (synced with MeowModAnalyzer.ps1)
# ---------------------------------------------------------------------------
suspiciousPatterns=(
    'AimAssist'
    'AnchorTweaks'
    'AutoAnchor'
    'AutoCrystal'
    'AutoDoubleHand'
    'JDWP.VirtualMachine.AllModules'
    'AutoHitCrystal'
    'AutoPot'
    'AutoTotem'
    'AutoArmor'
    'InventoryTotem'
    'LegitTotem'
    'PingSpoof'
    'SelfDestruct'
    'ShieldBreaker'
    'TriggerBot'
    'AxeSpam'
    'WebMacro'
    'FastPlace'
    'WalskyOptimizer'
    'WalksyOptimizer'
    'walsky.optimizer'
    'WalksyCrystalOptimizerMod'
    'Donut'
    'Replace Mod'
    'ShieldDisabler'
    'SilentAim'
    'Totem Hit'
    'Wtap'
    'FakeLag'
    'dev.virel'
    'orchard'
    'BlockESP'
    'dev.krypton'
    'dev/krypton'
    'skid.krypton'
    'skid/krypton'
    'AntiMissClick'
    'LagReach'
    'PopSwitch'
    'SprintReset'
    'ChestSteal'
    'AntiBot'
    'ElytraSwap'
    'FastXP'
    'FastExp'
    'Refill'
    'AirAnchor'
    'jnativehook'
    'FakeInv'
    'HoverTotem'
    'AutoClicker'
    'AutoFirework'
    'PackSpoof'
    'Antiknockback'
    'catlean'
    'AuthBypass'
    'Asteria'
    'Prestige'
    'AutoEat'
    'AutoMine'
    'MaceSwap'
    'Macro198'
    'StunSlam'
    'SafeAnchor'
    'DoubleAnchor'
    'AutoTPA'
    'BaseFinder'
    'Xenon'
    'gypsy'
    'AutoPotRefill'
    'KeyPearl'
    'AutoNethPot'
    'AutoDtap'
    'AutoWeb'
    'AnchorAction'
    'org.chainlibs.module.impl.modules.Crystal.Y'
    'org.chainlibs.module.impl.modules.Crystal.bF'
    'org.chainlibs.module.impl.modules.Crystal.bM'
    'org.chainlibs.module.impl.modules.Crystal.bY'
    'org.chainlibs.module.impl.modules.Crystal.bq'
    'org.chainlibs.module.impl.modules.Crystal.cv'
    'org.chainlibs.module.impl.modules.Crystal.o'
    'org.chainlibs.module.impl.modules.Blatant.I'
    'org.chainlibs.module.impl.modules.Blatant.bR'
    'org.chainlibs.module.impl.modules.Blatant.bx'
    'org.chainlibs.module.impl.modules.Blatant.cj'
    'org.chainlibs.module.impl.modules.Blatant.dk'
    'imgui.gl3'
    'imgui.glfw'
    'BowAim'
    'Criticals'
    'Fakenick'
    'FakeItem'
    'invsee'
    'ItemExploit'
    'Hellion'
    'hellion'
    'LicenseCheckMixin'
    'ClientPlayerInteractionManagerAccessor'
    'ClientPlayerEntityMixim'
    'dev.gambleclient'
    'obfuscatedAuth'
    'phantom-refmap.json'
    'xyz.greaj'
    'じ.class'
    'ふ.class'
    'ぶ.class'
    'ぷ.class'
    'た.class'
    'ね.class'
    'そ.class'
    'な.class'
    'ど.class'
    'ぐ.class'
    'ず.class'
    'で.class'
    'つ.class'
    'べ.class'
    'せ.class'
    'と.class'
    'み.class'
    'び.class'
    'す.class'
    'の.class'
)

cheatStrings=(
    'AutoCrystal'
    'autocrystal'
    'auto crystal'
    'cw crystal'
    'JDWP.VirtualMachine.AllModules'
    'dontPlaceCrystal'
    'dontBreakCrystal'
    'dev.virel'
    'orchard'
    'AutoHitCrystal'
    'autohitcrystal'
    'canPlaceCrystalServer'
    'healPotSlot'
    'ＡｕｔｏＣｒｙｓｔａｌ'
    'Ａｕｔｏ Ｃｒｙｓｔａｌ'
    'ＡｕｔｏＨｉｔＣｒｙｓｔａｌ'
    'AutoAnchor'
    'autoanchor'
    'auto anchor'
    'DoubleAnchor'
    'HasAnchor'
    'anchortweaks'
    'anchor macro'
    'safe anchor'
    'safeanchor'
    'SafeAnchor'
    'AirAnchor'
    'ＡｕｔｏＡｎｃｈｏｒ'
    'Ａｕｔｏ Ａｎｃｈｏｒ'
    'ＤｏｕｂｌｅＡｎｃｈｏｒ'
    'Ｄｏｕｂｌｅ Ａｎｃｈｏｒ'
    'ＳａｆｅＡｎｃｈｏｒ'
    'Ｓａｆｅ Ａｎｃｈｏｒ'
    'Ａｎｃｈｏｒ Ｍａｃｒｏ'
    'anchorMacro'
    'AutoTotem'
    'autototem'
    'auto totem'
    'InventoryTotem'
    'inventorytotem'
    'HoverTotem'
    'hover totem'
    'legittotem'
    'ＡｕｔｏＴｏｔｅｍ'
    'Ａｕｔｏ Ｔｏｔｅｍ'
    'ＨｏｖｅｒＴｏｔｅｍ'
    'Ｈｏｖｅｒ Ｔｏｔｅｍ'
    'ＩｎｖｅｎｔｏｒｙＴｏｔｅｍ'
    'Ａｕｔｏ Ｉｎｖｅｎｔｏｒｙ Ｔｏｔｅｍ'
    'Ａｕｔｏ Ｔｏｔｅｍ Ｈｉｔ'
    'AutoPot'
    'autopot'
    'auto pot'
    'speedPotSlot'
    'strengthPotSlot'
    'AutoArmor'
    'autoarmor'
    'auto armor'
    'ＡｕｔｏＰｏｔ'
    'Ａｕｔｏ Ｐｏｔ'
    'Ａｕｔｏ Ｐｏｔ Ｒｅｆｉｌｌ'
    'AutoPotRefill'
    'ＡｕｔｏＡｒｍｏｒ'
    'Ａｕｔｏ Ａｒｍｏｒ'
    'preventSwordBlockBreaking'
    'preventSwordBlockAttack'
    'ShieldDisabler'
    'ShieldBreaker'
    'ＳｈｉｅｌｄＤｉｓａｂｌｅｒ'
    'Ｓｈｉｅｌｄ Ｄｉｓａｂｌｅｒ'
    'Breaking shield with axe...'
    'AutoDoubleHand'
    'autodoublehand'
    'auto double hand'
    'ＡｕｔｏＤｏｕｂｌｅＨａｎｄ'
    'Ａｕｔｏ Ｄｏｕｂｌｅ Ｈａｎｄ'
    'AutoClicker'
    'ＡｕｔｏＣｌｉｃｋｅｒ'
    'Failed to switch to mace after axe!'
    'AutoMace'
    'MaceSwap'
    'SpearSwap'
    'ＡｕｔｏＭａｃｅ'
    'Ａｕｔｏ Ｍａｃｅ'
    'ＭａｃｅＳｗａｐ'
    'Ｍａｃｅ Ｓｗａｐ'
    'Ｓｐｅａｒ Ｓｗａｐ'
    'Ａｕｔｏｍａｔｉｃａｌｌｙ ａｘｅ ａｎｄ ｍａｃｅ ｓｈｉｅｌｄｅｄ ｐｌａｙｅｒｓ'
    'Ｓｔｕｎ Ｓｌａｍ'
    'StunSlam'
    'Donut'
    'JumpReset'
    'axespam'
    'axe spam'
    'findKnockbackSword'
    'attackRegisteredThisClick'
    'AimAssist'
    'aimassist'
    'aim assist'
    'triggerbot'
    'trigger bot'
    'ＡｉｍＡｓｓｉｓｔ'
    'Ａｉｍ Ａｓｓｉｓｔ'
    'ＴｒｉｇｇｅｒＢｏｔ'
    'Ｔｒｉｇｇｅｒ Ｂｏｔ'
    'Silent Rotations'
    'SilentRotations'
    'Ｓｉｌｅｎｔ Ｒｏｔａｔｉｏｎｓ'
    'FakeInv'
    'swapBackToOriginalSlot'
    'FakeLag'
    'pingspoof'
    'ping spoof'
    'ＦａｋｅＬａｇ'
    'Ｆａｋｅ Ｌａｇ'
    'fakePunch'
    'Fake Punch'
    'Ｆａｋｅ Ｐｕｎｃｈ'
    'mace_swap'
    'quick_strike'
    'macro_198'
    'stun_slam'
    'safe_anchor'
    'double_anchor'
    'auto_pot_refill'
    'walksy_optimizer'
    'key_pearl'
    'aim_assist'
    'auto_neth_pot'
    'auto_dtap'
    'trigger_bot'
    'auto_web'
    'DOUBLE_ESCAPE'
    'DOUBLE_RIGHTCLICK_FIRST'
    'DOUBLE_RIGHTCLICK_SECOND'
    'POST_CYCLE_DELAY'
    'PLACE_OBI'
    'WAIT_OBI'
    'PLACE_CRYSTAL'
    'BREAK_CRYSTAL'
    'ROTATING_DOWN'
    'ROTATING_BACK'
    'REFILLING'
    'PLANTING'
    'BONEMEALING'
    'AnchorAction'
    'Places two anchors for massive damage'
    'REOFFHAND_TOTEM'
    'webmacro'
    'web macro'
    'AntiWeb'
    'AutoWeb'
    'Ａｎｔｉ Ｗｅｂ'
    'ＡｕｔｏＷｅｂ'
    'Ｐｌａｃｅｓ Ｗｅｂｓ Ｏｎ Ｅｎｅｍｉｅｓ'
    'lvstrng'
    'dqrkis'
    'selfdestruct'
    'self destruct'
    'WalksyCrystalOptimizerMod'
    'WalksyOptimizer'
    'WalskyOptimizer'
    'Ｗａｌｋｓｙ Ｏｐｔｉｍｉｚｅｒ'
    'autoCrystalPlaceClock'
    'AutoFirework'
    'ElytraSwap'
    'FastXP'
    'FastExp'
    'NoJumpDelay'
    'ＥｌｙｔｒａＳｗａｐ'
    'Ｅｌｙｔｒａ Ｓｗａｐ'
    'PackSpoof'
    'Antiknockback'
    'catlean'
    'AuthBypass'
    'obfuscatedAuth'
    'LicenseCheckMixin'
    'BaseFinder'
    'invsee'
    'ItemExploit'
    'FreezePlayer'
    'Ｆｒｅｅｃａｍ'
    'Ｍｏｖｅ ｆｒｅｅｌｙ ｔｈｒｏｕｇｈ ｗａｌｌｓ'
    'Ｎｏ Ｃｌｉｐ'
    'Ｆｒｅｅｚｅ Ｐｌａｙｅｒ'
    'LWFH Crystal'
    'ＬＷＦＨ Ｃｒｙｓｔａｌ'
    'KeyPearl'
    'LootYeeter'
    'ＫｅｙＰｅａｒｌ'
    'Ｋｅｙ Ｐｅａｒｌ'
    'Ｌｏｏｔ Ｙｅｅｔｅｒ'
    'FastPlace'
    'Ｆａｓｔ Ｐｌａｃｅ'
    'Ｐｌａｃｅ ｂｌｏｃｋｓ ｆａｓｔｅｒ'
    'AutoBreach'
    'Ａｕｔｏ Ｂｒｅａｃｈ'
    'setBlockBreakingCooldown'
    'getBlockBreakingCooldown'
    'blockBreakingCooldown'
    'onBlockBreaking'
    'setItemUseCooldown'
    'invokeDoAttack'
    'invokeDoItemUse'
    'invokeOnMouseButton'
    'onPushOutOfBlocks'
    'onIsGlowing'
    'Automatically switches to sword when hitting with totem'
    'arrayOfString'
    'POT_CHEATS'
    'Dqrkis Client'
    'Entity.isGlowing'
    'Activate Key'
    'Ａｃｔｉｖａｔｅ Ｋｅｙ'
    'Click Simulation'
    'Ｃｌｉｃｋ Ｓｉｍｕｌａｔｉｏｎ'
    'On RMB'
    'Ｏｎ ＲＭＢ'
    'No Count Glitch'
    'Ｎｏ Ｃｏｕｎｔ Ｇｌｉｔｃｈ'
    'No Bounce'
    'NoBounce'
    'Ｎｏ Ｂｏｕｎｃｅ'
    'ＮｏＢｏｕｎｃｅ'
    'Ｒｅｍｏｖｅｓ ｔｈｅ ｃｒｙｓｔａｌ ｂｏｕｎｃｅ ａｎｉｍａｔｉｏｎ'
    'Place Delay'
    'Ｐｌａｃｅ Ｄｅｌａｙ'
    'Break Delay'
    'Ｂｒｅａｋ Ｄｅｌａｙ'
    'Ｆａｓｔ Ｍｏｄｅ'
    'Place Chance'
    'Ｐｌａｃｅ Ｃｈａｎｃｅ'
    'Break Chance'
    'Ｂｒｅａｋ Ｃｈａｎｃｅ'
    'Stop On Kill'
    'Ｓｔｏｐ Ｏｎ Ｋｉｌｌ'
    'Ｄａｍａｇｅ Ｔｉｃｋ'
    'damagetick'
    'Anti Weakness'
    'Ａｎｔｉ Ｗｅａｋｎｅｓｓ'
    'Particle Chance'
    'Ｐａｒｔｉｃｌｅ Ｃｈａｎｃｅ'
    'Trigger Key'
    'Ｔｒｉｇｇｅｒ Ｋｅｙ'
    'Switch Delay'
    'Ｓｗｉｔｃｈ Ｄｅｌａｙ'
    'Totem Slot'
    'Ｔｏｔｅｍ Ｓｌｏｔ'
    'Smooth Rotations'
    'Ｓｍｏｏｔｈ Ｒｏｔａｔｉｏｎｓ'
    'Rotation Speed'
    'Ｒｏｔａｔｉｏｎ Ｓｐｅｅｄ'
    'Use Easing'
    'Ｕｓｅ Ｅａｓｉｎｇ'
    'Easing Strength'
    'Ｅａｓｉｎｇ Ｓｔｒｅｎｇｔｈ'
    'While Use'
    'Ｗｈｉｌｅ Ｕｓｅ'
    'Stop on Kill'
    'Ｓｔｏｐ ｏｎ Ｋｉｌｌ'
    'Glowstone Delay'
    'Ｇｌｏｗｓｔｏｎｅ Ｄｅｌａｙ'
    'Glowstone Chance'
    'Ｇｌｏｗｓｔｏｎｅ Ｃｈａｎｃｅ'
    'Explode Delay'
    'Ｅｘｐｌｏｄｅ Ｄｅｌａｙ'
    'Explode Chance'
    'Ｅｘｐｌｏｄｅ Ｃｈａｎｃｅ'
    'Explode Slot'
    'Ｅｘｐｌｏｄｅ Ｓｌｏｔ'
    'Only Charge'
    'Ｏｎｌｙ Ｃｈａｒｇｅ'
    'Anchor Macro'
    'Reach Distance'
    'Ｒｅａｃｈ Ｄｉｓｔａｎｃｅ'
    'Min Height'
    'Ｍｉｎ Ｈｅｉｇｈｔ'
    'Min Fall Speed'
    'Ｍｉｎ Ｆａｌｌ Ｓｐｅｅｄ'
    'Attack Delay'
    'Ａｔｔａｃｋ Ｄｅｌａｙ'
    'Breach Delay'
    'Ｂｒｅａｃｈ Ｄｅｌａｙ'
    'Require Elytra'
    'Ｒｅｑｕｉｒｅ Ｅｌｙｔｒａ'
    'Auto Switch Back'
    'Ａｕｔｏ Ｓｗｉｔｃｈ Ｂａｃｋ'
    'Check Line of Sight'
    'Ｃｈｅｃｋ Ｌｉｎｅ ｏｆ Ｓｉｇｈｔ'
    'Only When Falling'
    'Ｏｎｌｙ Ｗｈｅｎ Ｆａｌｌｉｎｇ'
    'Require Crit'
    'Ｒｅｑｕｉｒｅ Ｃｒｉｔ'
    'Show Status Display'
    'Ｓｈｏｗ Ｓｔａｔｕｓ Ｄｉｓｐｌａｙ'
    'Stop On Crystal'
    'Ｓｔｏｐ Ｏｎ Ｃｒｙｓｔａｌ'
    'Check Shield'
    'Ｃｈｅｃｋ Ｓｈｉｅｌｄ'
    'On Pop'
    'Ｏｎ Ｐｏｐ'
    'Predict Damage'
    'Ｐｒｅｄｉｃｔ Ｄａｍａｇｅ'
    'On Ground'
    'Ｏｎ Ｇｒｏｕｎｄ'
    'Check Players'
    'Ｃｈｅｃｋ Ｐｌａｙｅｒｓ'
    'Predict Crystals'
    'Ｐｒｅｄｉｃｔ Ｃｒｙｓｔａｌｓ'
    'Check Aim'
    'Ｃｈｅｃｋ Ａｉｍ'
    'Check Items'
    'Ｃｈｅｃｋ Ｉｔｅｍｓ'
    'Activates Above'
    'Ａｃｔｉｖａｔｅｓ Ａｂｏｖｅ'
    'Blatant'
    'Ｂｌａｔａｎｔ'
    'Force Totem'
    'Ｆｏｒｃｅ Ｔｏｔｅｍ'
    'Stay Open For'
    'Ｓｔａｙ Ｏｐｅｎ Ｆｏｒ'
    'Auto Inventory Totem'
    'Only On Pop'
    'Ｏｎｌｙ Ｏｎ Ｐｏｐ'
    'Vertical Speed'
    'Ｖｅｒｔｉｃａｌ Ｓｐｅｅｄ'
    'Hover Totem'
    'Swap Speed'
    'Ｓｗａｐ Ｓｐｅｅｄ'
    'Strict One-Tick'
    'Ｓｔｒｉｃｔ Ｏｎｅ－Ｔｉｃｋ'
    'Mace Priority'
    'Ｍａｃｅ Ｐｒｉｏｒｉｔｙ'
    'Min Totems'
    'Ｍｉｎ Ｔｏｔｅｍｓ'
    'Min Pearls'
    'Ｍｉｎ Ｐｅａｒｌｓ'
    'Totem First'
    'Ｔｏｔｅｍ Ｆｉｒｓｔ'
    'Drop Interval'
    'Ｄｒｏｐ Ｉｎｔｅｒｖａｌ'
    'Random Pattern'
    'Ｒａｎｄｏｍ Ｐａｔｔｅｒｎ'
    'Loot Yeeter'
    'Horizontal Aim Speed'
    'Ｈｏｒｉｚｏｎｔａｌ Ａｉｍ Ｓｐｅｅｄ'
    'Vertical Aim Speed'
    'Ｖｅｒｔｉｃａｌ Ａｉｍ Ｓｐｅｅｄ'
    'Include Head'
    'Ｉｎｃｌｕｄｅ Ｈｅａｄ'
    'Web Delay'
    'Ｗｅｂ Ｄｅｌａｙ'
    'Holding Web'
    'Ｈｏｌｄｉｎｇ Ｗｅｂ'
    'Not When Affects Player'
    'Ｎｏｔ Ｗｈｅｎ Ａｆｆｅｃｔｓ Ｐｌａｙｅｒ'
    'Hit Delay'
    'Ｈｉｔ Ｄｅｌａｙ'
    'Ｓｗｉｔｃｈ Ｂａｃｋ'
    'Require Hold Axe'
    'Ｒｅｑｕｉｒｅ Ｈｏｌｄ Ａｘｅ'
    'placeInterval'
    'breakInterval'
    'stopOnKill'
    'activateOnRightClick'
    'holdCrystal'
    'ｐｌａｃｅＩｎｔｅｒｖａｌ'
    'ｂｒｅａｋＩｎｔｅｒｖａｌ'
    'ｓｔｏｐＯｎＫｉｌｌ'
    'ａｃｔｉｖａｔｅＯｎＲｉｇｈｔＣｌｉｃｋ'
    'ｄａｍａｇｅｔｉｃｋ'
    'ｈｏｌｄＣｒｙｓｔａｌ'
    'ｆａｋｅＰｕｎｃｈ'
    'Ｒｅｆｉｌｌｓ ｙｏｕｒ ｈｏｔｂａｒ ｗｉｔｈ ｐｏｔｉｏｎｓ'
    'Ｋｅｐｓ ｙｏｕ ｓｐｒｉｎｔｉｎｇ ａｔ ａｌｌ ｔｉｍｅｓ'
    'Ｐｌａｃｅｓ ａｎｃｈｏｒ， ｃｈａｒｇｅｓ ｉｔ， ｐｒｏｔｅｃｔｓ ｙｏｕ， ａｎｄ ｅｘｐｌｏｄｅｓ'
    'Ａｕｔｏ ｓｗａｐ ｔｏ ｓｐｅａｒ ｏｎ ａｔｔａｃｋ'
    'Macro Key'
    'Ｍａｃｒｏ Ｋｅｙ'
    'KillAura'
    'ClickAura'
    'MultiAura'
    'ForceField'
    'LegitAura'
    'AimBot'
    'AutoAim'
    'SilentAim'
    'AimLock'
    'HeadSnap'
    'CrystalAura'
    'AnchorAura'
    'AnchorFill'
    'AnchorPlace'
    'BedAura'
    'AutoBed'
    'BedBomb'
    'BedPlace'
    'BowAimbot'
    'BowSpam'
    'AutoBow'
    'AutoCrit'
    'CritBypass'
    'AlwaysCrit'
    'CriticalHit'
    'ReachHack'
    'ExtendReach'
    'LongReach'
    'HitboxExpand'
    'AntiKB'
    'NoKnockback'
    'GrimVelocity'
    'GrimDisabler'
    'VelocitySpoof'
    'KBReduce'
    'OffhandTotem'
    'TotemSwitch'
    'AutoWeapon'
    'AutoSword'
    'AutoCity'
    'Burrow'
    'SelfTrap'
    'HoleFiller'
    'AntiSurround'
    'AntiBurrow'
    'WTap'
    'TargetStrafe'
    'AutoGap'
    'AutoPearl'
    'FlyHack'
    'CreativeFlight'
    'BoatFly'
    'PacketFly'
    'AirJump'
    'SpeedHack'
    'BHop'
    'BunnyHop'
    'AntiFall'
    'NoFallDamage'
    'SafeFall'
    'StepHack'
    'FastClimb'
    'AutoStep'
    'HighStep'
    'WaterWalk'
    'LiquidWalk'
    'LavaWalk'
    'NoSlow'
    'NoSlowdown'
    'NoWeb'
    'NoSoulSand'
    'WallHack'
    'ElytraSpeed'
    'InstantElytra'
    'ScaffoldWalk'
    'FastBridge'
    'BuildHelper'
    'AutoBridge'
    'Nuker'
    'NukerLegit'
    'InstantBreak'
    'GhostHand'
    'NoSwing'
    'PlaceAssist'
    'AirPlace'
    'AutoPlace'
    'InstantPlace'
    'PlayerESP'
    'MobESP'
    'ItemESP'
    'StorageESP'
    'ChestESP'
    'Tracers'
    'NameTagsHack'
    'XRayHack'
    'OreFinder'
    'CaveFinder'
    'OreESP'
    'NewChunks'
    'ChunkBorders'
    'TunnelFinder'
    'TargetHUD'
    'ReachDisplay'
    'DoubleClicker'
    'JitterClick'
    'ButterflyClick'
    'CPSBoost'
    'ChestStealer'
    'InvManager'
    'InvMovebypass'
    'AutoSprint'
    'AntiAFK'
    'AutoRespawn'
    'PopSwitch'
    'FakeLatency'
    'FakePing'
    'SpoofRotation'
    'PositionSpoof'
    'GameSpeed'
    'SpeedTimer'
    'GrimBypass'
    'VulcanBypass'
    'MatrixBypass'
    'AACBypass'
    'VerusDisabler'
    'IntaveBypass'
    'WatchdogBypass'
    'PacketMine'
    'PacketWalk'
    'PacketSneak'
    'PacketCancel'
    'PacketDupe'
    'PacketSpam'
    'SelfDestruct'
    'HideClient'
    'SessionStealer'
    'TokenLogger'
    'TokenGrabber'
    'DiscordToken'
    'RemoteAccess'
    'ReverseShell'
    'C2Server'
    'Backdoor'
    'KeyLogger'
    'StashFinder'
    'TrailFinder'
    'imgui.binding'
    'JNativeHook'
    'GlobalScreen'
    'NativeKeyListener'
    'client-refmap.json'
    'cheat-refmap.json'
    'aHR0cDovL2FwaS5ub3ZhY2xpZW50LmxvbC93ZWJob29rLnR4dA=='
    'meteordevelopment'
    'cc/novoline'
    'com/alan/clients'
    'club/maxstats'
    'wtf/moonlight'
    'me/zeroeightsix/kami'
    'net/ccbluex'
    'today/opai'
    'net/minecraft/injection'
    'org/chainlibs/module/impl/modules'
    'xyz/greaj'
    'com/cheatbreaker'
    'com/moonsworth'
    'doomsdayclient'
    'DoomsdayClient'
    'doomsday.jar'
    'novaclient'
    'api.novaclient.lol'
    'vape.gg'
    'vapeclient'
    'VapeClient'
    'VapeLite'
    'intent.store'
    'IntentClient'
    'rise.today'
    'riseclient.com'
    'meteor-client'
    'meteorclient'
    'meteordevelopment.meteorclient'
    'liquidbounce'
    'fdp-client'
    'net.ccbluex'
    'novoware'
    'novoclient'
    'aristois'
    'impactclient'
    'azura'
    'pandaware'
    'skilled'
    'moonClient'
    'astolfo'
    'futureClient'
    'konas'
    'rusherhack'
    'inertia'
    'exhibition'
    'dev.krypton'
    'dev/krypton'
    'skid.krypton'
    'skid/krypton'
    'VirginClient'
    'virgin client'
    'CatleanClient'
    'catlean client'
    'ArgonClient'
    'argon client'
    'Asteria'
    'AsteriaClient'
    'asteria client'
    'Prestige'
    'PrestigeClient'
    'prestige client'
    'prestigeclient.vip'
    'gypsy'
    'GypsyClient'
    'gypsy client'
    'Xenon'
    'XenonClient'
    'xenon client'
    'GrimClient'
    'grim client'
    'phantom-refmap.json'
    'dqrkis.xyz'
)

: > "$PATTERNS_FILE"
for __p in "${suspiciousPatterns[@]}"; do
    printf '%s\n' "$__p" >> "$PATTERNS_FILE"
done

: > "$CHEAT_FILE"
for __s in "${cheatStrings[@]}"; do
    printf '%s\n' "$__s" >> "$CHEAT_FILE"
done

# Cheat strings that contain fullwidth characters (for ＡｕｔｏＣｒｙｓｔａｌ resolution)
perl -ne 'print if /(?:\xEF\xBC[\xA1-\xBA\x90-\x99]|\xEF\xBD[\x81-\x9A])/' \
    "$CHEAT_FILE" > "$FW_POOL_FILE"

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
repeat_char() {
    local ch=$1 n=$2 s
    [ "$n" -lt 0 ] && n=0
    printf -v s '%*s' "$n" ''
    printf '%s' "${s// /$ch}"
}

write_rule() { # char width color
    printf '%s%s%s\n' "$3" "$(repeat_char "$1" "$2")" "$C_RESET"
}

write_section_header() { # title count dotcolor countcolor
    printf '\n  %s●%s  %s%s%s  %s(%s)%s\n\n' \
        "$3" "$C_RESET" "$C_WHITE" "$1" "$C_RESET" "$4" "$2" "$C_RESET"
}

json_key() { # key (JSON on stdin)
    perl "$SCAN_PL" jsonkey "$1" 2>/dev/null
}

file_sha1() {
    case "$SHA1_TOOL" in
        sha1sum) sha1sum -- "$1" 2>/dev/null | awk '{print $1}' ;;
        shasum)  shasum -a 1 -- "$1" 2>/dev/null | awk '{print $1}' ;;
        openssl) openssl dgst -sha1 -r "$1" 2>/dev/null | awk '{print $1}' ;;
    esac
}

get_download_source() { # path -> source name (or nothing)
    local file=$1 url=""

    if command -v getfattr >/dev/null 2>&1; then
        url=$(getfattr --only-values -n user.xdg.origin.url -- "$file" 2>/dev/null | tr -d '\r\n\000')
    fi
    if [ -z "$url" ] && command -v xattr >/dev/null 2>&1; then
        url=$(xattr -p user.xdg.origin.url -- "$file" 2>/dev/null | tr -d '\r\n\000')
        if [ -z "$url" ]; then
            url=$(xattr -p com.apple.metadata:kMDItemWhereFroms -- "$file" 2>/dev/null \
                | grep -aoE 'https?://[^"<> ]+' | head -n 1)
        fi
    fi
    [ -z "$url" ] && return 0

    case "$url" in
        *mediafire.com*)                                            echo "MediaFire" ;;
        *discord.com*|*discordapp.com*|*cdn.discordapp.com*)        echo "Discord" ;;
        *dropbox.com*)                                              echo "Dropbox" ;;
        *drive.google.com*)                                         echo "Google Drive" ;;
        *mega.nz*|*mega.co.nz*)                                     echo "MEGA" ;;
        *github.com*)                                               echo "GitHub" ;;
        *modrinth.com*)                                             echo "Modrinth" ;;
        *curseforge.com*)                                           echo "CurseForge" ;;
        *anydesk.com*)                                              echo "AnyDesk" ;;
        *doomsdayclient.com*)                                       echo "DoomsdayClient" ;;
        *prestigeclient.vip*)                                       echo "PrestigeClient" ;;
        *198macros.com*)                                            echo "198Macros" ;;
        *dqrkis.xyz*)                                               echo "Dqrkis" ;;
        *)
            if [[ $url =~ https?://(www\.)?([^/]+) ]]; then
                echo "${BASH_REMATCH[2]}"
            else
                echo "$url"
            fi
            ;;
    esac
}

query_modrinth() { # hash -> "name|slug"
    local hash=$1 version_json project_id project_json title slug
    version_json=$(curl -sf --max-time 15 "https://api.modrinth.com/v2/version_file/$hash" 2>/dev/null) || true
    [ -z "$version_json" ] && { echo "|"; return; }

    project_id=$(printf '%s' "$version_json" | json_key project_id)
    [ -z "$project_id" ] && { echo "|"; return; }

    project_json=$(curl -sf --max-time 15 "https://api.modrinth.com/v2/project/$project_id" 2>/dev/null) || true
    [ -z "$project_json" ] && { echo "|"; return; }

    title=$(printf '%s' "$project_json" | json_key title)
    slug=$(printf '%s' "$project_json" | json_key slug)
    echo "$title|$slug"
}

query_megabase() { # hash -> name
    local hash=$1 response
    response=$(curl -sf --max-time 20 "https://megabase.vercel.app/api/query?hash=$hash" 2>/dev/null) || true
    [ -z "$response" ] && return 0
    if printf '%s' "$response" | grep -Eq '"error"[[:space:]]*:[[:space:]]*true'; then
        return 0
    fi
    printf '%s' "$response" | json_key name
}

# ---------------------------------------------------------------------------
# Java process helpers
# ---------------------------------------------------------------------------
process_cmdline() {
    local pid=$1
    if [ -r "/proc/$pid/cmdline" ]; then
        tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null
    else
        ps -p "$pid" -o command= 2>/dev/null
    fi
}

find_java_pid() {
    local pid cmd fallback=""
    [ "$HAVE_PGREP" -eq 1 ] || return 0
    for pid in $(pgrep -x javaw 2>/dev/null) $(pgrep -x java 2>/dev/null); do
        cmd=$(process_cmdline "$pid")
        if printf '%s' "$cmd" | grep -qiE 'minecraft|fabric|forge|net\.minecraft'; then
            echo "$pid"
            return 0
        fi
        [ -z "$fallback" ] && fallback=$pid
    done
    [ -n "$fallback" ] && echo "$fallback"
}

parse_etime() { # [[dd-]hh:]mm:ss -> seconds
    local e=$1 d=0 h=0 m=0 s=0
    if [[ $e == *-* ]]; then
        d=${e%%-*}
        e=${e#*-}
    fi
    local IFS=':'
    set -- $e
    case $# in
        3) h=$((10#${1:-0})); m=$((10#${2:-0})); s=$((10#${3:-0})) ;;
        2) m=$((10#${1:-0})); s=$((10#${2:-0})) ;;
        1) s=$((10#${1:-0})) ;;
    esac
    echo $((d * 86400 + h * 3600 + m * 60 + s))
}

process_uptime() { # pid -> seconds
    local pid=$1 up
    if [ -r "/proc/$pid/stat" ]; then
        local ticks btime hz
        ticks=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null)
        btime=$(awk '/^btime/{print $2; exit}' /proc/stat 2>/dev/null)
        hz=$(getconf CLK_TCK 2>/dev/null || echo 100)
        if [ -n "$ticks" ] && [ -n "$btime" ] && [ "$hz" -gt 0 ] 2>/dev/null; then
            up=$(( $(date +%s) - (btime + ticks / hz) ))
            echo "$up"
            return
        fi
    fi
    up=$(ps -p "$pid" -o etimes= 2>/dev/null | tr -d '[:space:]')
    if [ -z "$up" ]; then
        up=$(ps -p "$pid" -o etime= 2>/dev/null | tr -d '[:space:]')
        [ -n "$up" ] && up=$(parse_etime "$up")
    fi
    echo "${up:-0}"
}

# ---------------------------------------------------------------------------
# Scan-scope helpers
# ---------------------------------------------------------------------------
is_windows_shell() {
    case "$OSTYPE" in
        msys*|cygwin*|win32*) return 0 ;;
    esac
    return 1
}

is_system_dir() { # path -> 0 if it is a home/system directory
    local p=$1 lower prefix
    [ -z "$p" ] && return 1
    p=${p%/}
    [ -z "$p" ] && p="/"
    [ "$p" = "$HOME" ] && return 0
    [ "$p" = "/" ] && return 0
    for prefix in /bin /sbin /usr /lib /lib64 /lib32 /etc /var /opt /boot /run /proc /sys /dev /snap /nix /System /Library /Applications /private; do
        case "$p" in
            "$prefix"|"$prefix"/*) return 0 ;;
        esac
    done
    lower=$(printf '%s' "$p" | tr '[:upper:]' '[:lower:]')
    case "$lower" in
        c:/windows|c:/windows/*|c:/program\ files|c:/program\ files/*|c:/program\ files\ \(x86\)|c:/program\ files\ \(x86\)/*|c:/programdata|c:/programdata/*)
            return 0 ;;
        /mnt/c/windows|/mnt/c/windows/*|/mnt/c/program\ files|/mnt/c/program\ files/*|/mnt/c/program\ files\ \(x86\)|/mnt/c/program\ files\ \(x86\)/*|/mnt/c/programdata|/mnt/c/programdata/*|/c/windows|/c/windows/*|/c/program\ files|/c/program\ files/*|/c/program\ files\ \(x86\)|/c/program\ files\ \(x86\)/*)
            return 0 ;;
    esac
    return 1
}

default_minecraft_mods() {
    local p="" winappdata
    case "$OSTYPE" in
        darwin*)
            p="$HOME/Library/Application Support/minecraft/mods"
            ;;
        msys*|cygwin*|win32*)
            p="${APPDATA:-$HOME/AppData/Roaming}/.minecraft/mods"
            ;;
        *)
            if grep -qi microsoft /proc/version 2>/dev/null && command -v cmd.exe >/dev/null 2>&1 && command -v wslpath >/dev/null 2>&1; then
                winappdata=$(cmd.exe /c echo %APPDATA% 2>/dev/null | tr -d '\r\n')
                if [ -n "$winappdata" ]; then
                    p="$(wslpath -u "$winappdata" 2>/dev/null)/.minecraft/mods"
                fi
            fi
            [ -z "$p" ] && p="$HOME/.minecraft/mods"
            ;;
    esac
    printf '%s' "$p"
}

default_custom_path() {
    if [ -n "$PWD" ] && ! is_system_dir "$PWD"; then
        printf '%s' "$PWD"
    else
        default_minecraft_mods
    fi
}

is_skipped_jar_path() {
    local p=$1 lp base lb
    lp=$(printf '%s' "$p" | tr '[:upper:]' '[:lower:]')
    case "$lp" in
        */.fabric/processedmods/*|*/.fabric/processedmods|*\\.fabric\\processedmods\\*|*\\.fabric\\processedmods)
            return 0 ;;
        */libraries/*|*/versions/*|*/runtime/*|*/jre/*|*/jdk/*|*/.gradle/*|*/.m2/*|*/loom-cache/*)
            return 0 ;;
        *\\libraries\\*|*\\versions\\*|*\\runtime\\*|*\\jre\\*|*\\jdk\\*|*\\.gradle\\*|*\\.m2\\*|*\\loom-cache\\*)
            return 0 ;;
    esac
    base=${p##*/}
    base=${base##*\\}
    [ -z "$base" ] && return 1
    lb=$(printf '%s' "$base" | tr '[:upper:]' '[:lower:]')
    case "$lb" in
        minecraft*.jar|forge-*.jar|neoforge-*.jar|fabric-loader*.jar|quilt-loader*.jar|authlib*.jar|brigadier*.jar|datafixerupper*.jar|log4j*.jar|netty*.jar|guava*.jar|gson*.jar|asm-*.jar|jopt-simple*.jar|commons-*.jar|slf4j*.jar|lwjgl*.jar|jna*.jar|joml*.jar|oshi*.jar|text2speech*.jar)
            return 0 ;;
        gradle-wrapper*.jar|remapped.*.jar|remapped-*.jar)
            return 0 ;;
    esac
    return 1
}

is_skipped_archive_entry() { # entry path inside an archive
    local e
    e=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    case "$e" in
        */libraries/*|libraries/*|*/versions/*|versions/*|*/runtime/*|runtime/*|*/jre/*|jre/*|*/jdk/*|jdk/*|*/loom-cache/*|loom-cache/*)
            return 0 ;;
        */.fabric/processedmods/*|.fabric/processedmods/*|*\\.fabric\\processedmods\\*|.fabric\\processedmods\\*)
            return 0 ;;
    esac
    return 1
}

add_jar_file() {
    local p=$1
    [ -f "$p" ] && [ -r "$p" ] || return 0
    is_skipped_jar_path "$p" && return 0
    jarFiles+=("$p")
}

collect_mods_dir_jars() { # dir
    local dir=$1 j
    [ -d "$dir" ] || return 0
    while IFS= read -r j; do
        [ -n "$j" ] && add_jar_file "$j"
    done < <(find "$dir" -maxdepth 1 -type f -iname '*.jar' 2>/dev/null)
}

collect_launcher_jars() {
    local dirs=() bases=() lunar=() seen=() root d inst base dup
    local j

    dirs+=("$(default_minecraft_mods)")

    if is_windows_shell; then
        bases+=("${APPDATA:-$HOME/AppData/Roaming}/PrismLauncher/instances")
        lunar+=("$HOME/.lunarclient")
    else
        bases+=("$HOME/.local/share/PrismLauncher/instances")
        bases+=("$HOME/.var/app/org.prismlauncher.PrismLauncher/data/PrismLauncher/instances")
        bases+=("$HOME/Library/Application Support/PrismLauncher/instances")
        lunar+=("$HOME/.lunarclient")
        lunar+=("$HOME/Library/Application Support/lunarclient")
    fi

    for base in "${bases[@]}"; do
        [ -d "$base" ] || continue
        while IFS= read -r inst; do
            [ -n "$inst" ] || continue
            dirs+=("$inst/minecraft/mods")
            dirs+=("$inst/.minecraft/mods")
        done < <(find "$base" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
    done

    for root in "${lunar[@]}"; do
        [ -d "$root" ] || continue
        while IFS= read -r d; do
            [ -n "$d" ] && dirs+=("$d")
        done < <(find "$root" -type d -iname 'mods' 2>/dev/null)
    done

    for d in "${dirs[@]}"; do
        [ -d "$d" ] || continue
        dup=0
        for inst in "${seen[@]}"; do
            [ "$inst" = "$d" ] && dup=1
        done
        [ "$dup" -eq 1 ] && continue
        seen+=("$d")
        printf '%s   • %s%s\n' "$C_GRAY" "$d" "$C_RESET"
        collect_mods_dir_jars "$d"
    done

    if [ ${#seen[@]} -eq 0 ]; then
        printf '%s   (no launcher mod folders found)%s\n' "$C_YELLOW" "$C_RESET"
    fi
}

extract_archive_jars() { # archive index
    local archive=$1 idx=$2 lower dest entry base
    lower=$(printf '%s' "$archive" | tr '[:upper:]' '[:lower:]')
    dest="$TMPROOT/archives/$idx"
    mkdir -p "$dest" 2>/dev/null || return 0
    printf '%s' "$archive" > "$dest/.origin" 2>/dev/null || true

    case "$lower" in
        *.zip|*.mcpack)
            if command -v unzip >/dev/null 2>&1; then
                while IFS= read -r entry; do
                    [ -n "$entry" ] || continue
                    is_skipped_archive_entry "$entry" && continue
                    base=${entry##*/}
                    [ -n "$base" ] || continue
                    unzip -p "$archive" "$entry" > "$dest/$base" 2>/dev/null || rm -f "$dest/$base"
                done < <(unzip -Z1 "$archive" 2>/dev/null | grep -iE '\.jar$')
            fi
            ;;
        *.tar.gz|*.tgz|*.tar)
            if command -v tar >/dev/null 2>&1; then
                while IFS= read -r entry; do
                    [ -n "$entry" ] || continue
                    is_skipped_archive_entry "$entry" && continue
                    base=${entry##*/}
                    [ -n "$base" ] || continue
                    tar -xOf "$archive" "$entry" > "$dest/$base" 2>/dev/null || rm -f "$dest/$base"
                done < <(tar -tf "$archive" 2>/dev/null | grep -iE '\.jar$')
            fi
            ;;
        *.rar)
            if command -v unrar >/dev/null 2>&1; then
                while IFS= read -r entry; do
                    [ -n "$entry" ] || continue
                    is_skipped_archive_entry "$entry" && continue
                    base=${entry##*/}
                    [ -n "$base" ] || continue
                    unrar p -inul "$archive" "$entry" > "$dest/$base" 2>/dev/null || rm -f "$dest/$base"
                done < <(unrar lb "$archive" 2>/dev/null | grep -iE '\.jar$')
            elif command -v 7z >/dev/null 2>&1; then
                7z x -y -o"$dest" "$archive" '*.jar' >/dev/null 2>&1 || true
            elif command -v bsdtar >/dev/null 2>&1; then
                while IFS= read -r entry; do
                    [ -n "$entry" ] || continue
                    is_skipped_archive_entry "$entry" && continue
                    base=${entry##*/}
                    [ -n "$base" ] || continue
                    bsdtar -xOf "$archive" "$entry" > "$dest/$base" 2>/dev/null || rm -f "$dest/$base"
                done < <(bsdtar -tf "$archive" 2>/dev/null | grep -iE '\.jar$')
            elif command -v unar >/dev/null 2>&1; then
                unar -q -o "$dest" "$archive" >/dev/null 2>&1 || true
            fi
            ;;
        *.7z)
            if command -v 7z >/dev/null 2>&1; then
                7z x -y -o"$dest" "$archive" '*.jar' >/dev/null 2>&1 || true
            elif command -v bsdtar >/dev/null 2>&1; then
                while IFS= read -r entry; do
                    [ -n "$entry" ] || continue
                    is_skipped_archive_entry "$entry" && continue
                    base=${entry##*/}
                    [ -n "$base" ] || continue
                    bsdtar -xOf "$archive" "$entry" > "$dest/$base" 2>/dev/null || rm -f "$dest/$base"
                done < <(bsdtar -tf "$archive" 2>/dev/null | grep -iE '\.jar$')
            fi
            ;;
    esac

    while IFS= read -r entry; do
        [ -n "$entry" ] && add_jar_file "$entry"
    done < <(find "$dest" -type f -iname '*.jar' 2>/dev/null)
}

collect_system_jars() {
    local roots=() prune=() archives=()
    local root f lf d first=1 i=0 archive

    if is_windows_shell; then
        for root in /c /d /e /f /g /h /i /j /k /l /m /n /o /p /q /r /s /t /u /v /w /x /y /z; do
            [ -d "$root" ] && roots+=("$root")
        done
        [ ${#roots[@]} -eq 0 ] && roots=("/")
    else
        roots=("/")
    fi

    prune=( -type d \( )
    for d in /System /private /Applications /cores /tmp; do
        if [ $first -eq 1 ]; then first=0; else prune+=( -o ); fi
        prune+=( -path "$d" )
    done
    for d in .git .svn .hg node_modules __pycache__ .cache .gradle .m2 loom-cache \
             proc sys dev run usr lib lib32 lib64 bin sbin etc boot var nix snap \
             libraries versions runtime jre jdk processedMods assets natives \
             "System Volume Information" Windows "Program Files" "Program Files (x86)" \
             ProgramData Windows.old Recovery PerfLogs; do
        if [ $first -eq 1 ]; then first=0; else prune+=( -o ); fi
        prune+=( -iname "$d" )
    done
    prune+=( \) -prune )

    printf '%s   searching: %s%s\n' "$C_GRAY" "${roots[*]}" "$C_RESET"
    for root in "${roots[@]}"; do
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            lf=$(printf '%s' "$f" | tr '[:upper:]' '[:lower:]')
            case "$lf" in
                *.jar) add_jar_file "$f" ;;
                *)     archives+=("$f") ;;
            esac
        done < <(find "$root" \
            -path "$TMPROOT" -prune -o \
            "${prune[@]}" -o \
            -type f \( -iname '*.jar' -o -iname '*.zip' -o -iname '*.mcpack' -o -iname '*.tar.gz' -o -iname '*.tgz' -o -iname '*.tar' -o -iname '*.rar' -o -iname '*.7z' \) -print 2>/dev/null)
    done

    printf '%s   archives found: %s%s\n' "$C_GRAY" "${#archives[@]}" "$C_RESET"
    for archive in "${archives[@]}"; do
        i=$((i + 1))
        extract_archive_jars "$archive" "$i"
    done
}

collect_custom_jars() {
    collect_mods_dir_jars "$modsPath"
}

# ---------------------------------------------------------------------------
# Banner / input
# ---------------------------------------------------------------------------
clear 2>/dev/null || true

banner=$(cat <<'BANNER'

  ███╗   ███╗███████╗ ██████╗ ██╗    ██╗  ███╗   ███╗ ██████╗ ██████╗
  ████╗ ████║██╔════╝██╔═══██╗██║    ██║  ████╗ ████║██╔═══██╗██╔══██╗
  ██╔████╔██║█████╗  ██║   ██║██║ █╗ ██║  ██╔████╔██║██║   ██║██║  ██║
  ██║╚██╔╝██║██╔══╝  ██║   ██║██║███╗██║  ██║╚██╔╝██║██║   ██║██║  ██║
  ██║ ╚═╝ ██║███████╗╚██████╔╝╚███╔███╔╝  ██║ ╚═╝ ██║╚██████╔╝██████╔╝
  ╚═╝     ╚═╝╚══════╝ ╚═════╝  ╚══╝╚══╝   ╚═╝     ╚═╝ ╚═════╝ ╚═════╝

   █████╗ ███╗   ██╗ █████╗ ██╗   ██╗   ██╗███████╗███████╗██████╗
  ██╔══██╗████╗  ██║██╔══██╗██║   ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
  ███████║██╔██╗ ██║███████║██║    ╚████╔╝   ███╔╝ █████╗  ██████╔╝
  ██╔══██║██║╚██╗██║██╔══██║██║     ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
  ██║  ██║██║ ╚████║██║  ██║███████╗ ██║   ███████╗███████╗██║  ██║
  ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝ ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝

                         \    /\
                          )  ( ')
                         (  /  )
                          \(__)|

BANNER
)

printf '%s%s%s\n' "$C_CYAN" "$banner" "$C_RESET"
printf '\n'
printf '%s                Made with %s' "$C_GRAY" "$C_RESET"
printf '%s♥ %s' "$C_RED" "$C_RESET"
printf '%sby %s' "$C_GRAY" "$C_RESET"
printf '%sMeowTonynoh%s\n' "$C_CYAN" "$C_RESET"
printf '\n'
write_rule "━" 76 "$C_DARKCYAN"
printf '\n'

printf '%sSelect scan scope:%s\n' "$C_WHITE" "$C_RESET"
printf '  %s1)%s Whole system %s(jars + .zip/.tar.gz/.rar/.mcpack archives + recycle bin)%s\n' \
    "$C_CYAN" "$C_RESET" "$C_DARKGRAY" "$C_RESET"
printf '  %s2)%s Launchers only %s(PrismLauncher + Lunar + .minecraft)%s\n' \
    "$C_CYAN" "$C_RESET" "$C_DARKGRAY" "$C_RESET"
printf '  %s3)%s Custom folder %s(default: %s)%s\n' \
    "$C_CYAN" "$C_RESET" "$C_DARKGRAY" "$(default_custom_path)" "$C_RESET"
printf 'Choice %s[3]%s: ' "$C_DARKGRAY" "$C_RESET"
IFS= read -r scanChoice
[ -z "$scanChoice" ] && scanChoice=3
while [ "$scanChoice" != 1 ] && [ "$scanChoice" != 2 ] && [ "$scanChoice" != 3 ]; do
    printf '%sPlease enter 1, 2 or 3: %s' "$C_YELLOW" "$C_RESET"
    IFS= read -r scanChoice
    [ -z "$scanChoice" ] && scanChoice=3
done
printf '\n'

modsPath=""
case "$scanChoice" in
    1) scanMode="system" ;;
    2) scanMode="launchers" ;;
    3)
        scanMode="custom"
        defPath=$(default_custom_path)
        printf 'Enter path to the mods folder: '
        printf '%s(press Enter to use default)%s\n' "$C_DARKGRAY" "$C_RESET"
        printf 'PATH %s[%s]%s: ' "$C_DARKGRAY" "$defPath" "$C_RESET"
        IFS= read -r modsPath
        printf '\n'

        # trim whitespace and matching quotes
        modsPath="${modsPath#"${modsPath%%[![:space:]]*}"}"
        modsPath="${modsPath%"${modsPath##*[![:space:]]}"}"
        case "$modsPath" in
            \"*\") modsPath=${modsPath#\"}; modsPath=${modsPath%\"} ;;
            \'*\') modsPath=${modsPath#\'}; modsPath=${modsPath%\'} ;;
        esac

        if [ -z "$modsPath" ]; then
            modsPath=$defPath
            printf 'Continuing with %s%s%s\n\n' "$C_WHITE" "$modsPath" "$C_RESET"
        fi

        # expand a leading ~
        case "$modsPath" in
            "~"|"~/"*) modsPath="$HOME${modsPath#\~}" ;;
        esac

        if [ ! -d "$modsPath" ]; then
            printf '%s❌ Invalid Path!%s\n' "$C_RED" "$C_RESET"
            printf '%sThe directory does not exist or is not accessible.%s\n\n' "$C_YELLOW" "$C_RESET"
            printf '%sTried to access: %s%s\n\n' "$C_GRAY" "$modsPath" "$C_RESET"
            printf '%sPress any key to exit...%s\n' "$C_GRAY" "$C_RESET"
            IFS= read -r -n 1 -s
            exit 1
        fi

        if [ ! -r "$modsPath" ] || [ ! -x "$modsPath" ]; then
            printf '%s❌ Error accessing directory: %s%s\n' "$C_RED" "$modsPath" "$C_RESET"
            printf '%sPress any key to exit...%s\n' "$C_GRAY" "$C_RESET"
            IFS= read -r -n 1 -s
            exit 1
        fi
        ;;
esac

case "$scanMode" in
    system)
        printf '%s📁 Scan scope: %s%s\n\n' "$C_GREEN" "whole system (recycle bin included)" "$C_RESET"
        printf '%s⚠️  Whole-system scans can take a long time (archive extraction + network lookups).%s\n\n' "$C_YELLOW" "$C_RESET"
        scanWhere="the whole system"
        ;;
    launchers)
        printf '%s📁 Scan scope: %s%s\n\n' "$C_GREEN" "PrismLauncher / Lunar / .minecraft" "$C_RESET"
        scanWhere="the launcher mod folders"
        ;;
    custom)
        printf '%s📁 Scanning directory: %s%s\n\n' "$C_GREEN" "$modsPath" "$C_RESET"
        scanWhere="$modsPath"
        ;;
esac

# ---------------------------------------------------------------------------
# Minecraft process uptime
# ---------------------------------------------------------------------------
JAVA_PID=$(find_java_pid)

if [ -n "$JAVA_PID" ]; then
    uptime_secs=$(process_uptime "$JAVA_PID")
    start_time=$(ps -p "$JAVA_PID" -o lstart= 2>/dev/null | sed 's/^[[:space:]]*//')
    proc_name=$(ps -p "$JAVA_PID" -o comm= 2>/dev/null | sed 's/^[[:space:]]*//')
    proc_name=${proc_name##*/}
    up_h=$(( (uptime_secs % 86400) / 3600 ))
    up_m=$(( (uptime_secs % 3600) / 60 ))
    up_s=$(( uptime_secs % 60 ))

    printf '%s🕒 { Minecraft Uptime }%s\n' "$C_DARKCYAN" "$C_RESET"
    printf '%s   %s PID %s started at %s%s\n' "$C_GRAY" "$proc_name" "$JAVA_PID" "$start_time" "$C_RESET"
    printf '%s   Running for: %sh %sm %ss%s\n\n' "$C_GRAY" "$up_h" "$up_m" "$up_s" "$C_RESET"
fi

# ---------------------------------------------------------------------------
# JAR enumeration
# ---------------------------------------------------------------------------
jarFiles=()
case "$scanMode" in
    system)    collect_system_jars ;;
    launchers) collect_launcher_jars ;;
    custom)    collect_custom_jars ;;
esac

totalFiles=${#jarFiles[@]}

if [ "$totalFiles" -eq 0 ]; then
    printf '%s⚠️  No JAR files found in: %s%s\n' "$C_YELLOW" "$scanWhere" "$C_RESET"
    printf '%sPress any key to exit...%s\n' "$C_GRAY" "$C_RESET"
    IFS= read -r -n 1 -s
    exit 0
fi

fileWord="files"
modWord="mods"
[ "$totalFiles" -eq 1 ] && { fileWord="file"; modWord="mod"; }
printf '%s🔍 Found %s JAR %s to analyze%s\n\n' "$C_GREEN" "$totalFiles" "$fileWord" "$C_RESET"

# ---------------------------------------------------------------------------
# Result stores
# ---------------------------------------------------------------------------
verifiedNames=(); verifiedFiles=(); verifiedPaths=(); verifiedWhite=()
unknownFiles=(); unknownSources=(); unknownPaths=()
suspFiles=(); suspPatterns=(); suspStrings=(); suspFullwidth=(); suspPaths=()
bypassFiles=(); bypassFlags=(); bypassPaths=()
obfFiles=(); obfFlags=(); obfPaths=()
jvmFlags=()

# Full path for a result entry. In whole-system/launcher scans the analyzed
# path is shown; archive members show "<archive> → <member>" instead of the
# temporary extraction path.
full_mod_path() {
    local p=$1 d origin
    case "$p" in
        "$TMPROOT"/archives/*)
            d=$(dirname "$p")
            if [ -f "$d/.origin" ]; then
                origin=$(cat "$d/.origin" 2>/dev/null)
                if [ -n "$origin" ]; then
                    printf '%s → %s' "$origin" "${p##*/}"
                    return
                fi
            fi
            ;;
    esac
    printf '%s' "$p"
}

# Console label: full path for whole-system/launcher scans, filename otherwise.
result_label() { # basename fullpath
    case "$scanMode" in
        system|launchers) full_mod_path "$2" ;;
        *) printf '%s' "$1" ;;
    esac
}

remove_verified() {
    local target=$1 i
    local nName=() nFile=() nPath=() nWhite=()
    for ((i = 0; i < ${#verifiedFiles[@]}; i++)); do
        if [ "${verifiedFiles[i]}" != "$target" ]; then
            nName+=("${verifiedNames[i]}")
            nFile+=("${verifiedFiles[i]}")
            nPath+=("${verifiedPaths[i]}")
            nWhite+=("${verifiedWhite[i]}")
        fi
    done
    verifiedNames=("${nName[@]}")
    verifiedFiles=("${nFile[@]}")
    verifiedPaths=("${nPath[@]}")
    verifiedWhite=("${nWhite[@]}")
}

remove_unknown() {
    local target=$1 i
    local nFile=() nSource=() nPath=()
    for ((i = 0; i < ${#unknownFiles[@]}; i++)); do
        if [ "${unknownFiles[i]}" != "$target" ]; then
            nFile+=("${unknownFiles[i]}")
            nSource+=("${unknownSources[i]}")
            nPath+=("${unknownPaths[i]}")
        fi
    done
    unknownFiles=("${nFile[@]}")
    unknownSources=("${nSource[@]}")
    unknownPaths=("${nPath[@]}")
}

is_modrinth_whitelisted() {
    local target=$1 i
    for ((i = 0; i < ${#verifiedFiles[@]}; i++)); do
        if [ "${verifiedFiles[i]}" = "$target" ] && [ "${verifiedWhite[i]}" = "true" ]; then
            return 0
        fi
    done
    return 1
}

in_list() { # needle list...
    local needle=$1 item
    shift
    for item in "$@"; do
        [ "$item" = "$needle" ] && return 0
    done
    return 1
}

# ---------------------------------------------------------------------------
# Pass 2 — pattern / string / fullwidth scan
# ---------------------------------------------------------------------------
scan_patterns_to() { # input output
    perl "$SCAN_PL" patterns "$1" "$PATTERNS_FILE" 2>/dev/null | LC_ALL=C sort -u > "$2"
}
scan_strings_to() { # input output
    perl "$SCAN_PL" strings "$1" "$CHEAT_FILE" 2>/dev/null | LC_ALL=C sort -u > "$2"
}
scan_fullwidth_to() { # input output
    perl "$SCAN_PL" fullwidth "$1" 2>/dev/null | LC_ALL=C sort -u > "$2"
}
resolve_fullwidth_to() { # found output
    perl "$SCAN_PL" resolve "$1" "$FW_POOL_FILE" 2>/dev/null | LC_ALL=C sort -u > "$2"
}

deep_scan() { # jar workdir
    local jar=$1 work=$2
    local names="$work/names" nestedList="$work/nested.list" content="$work/content"
    local pats="$work/pats" strs="$work/strs" fw="$work/fw" fwres="$work/fwres"

    : > "$names"; : > "$content"; : > "$pats"; : > "$strs"; : > "$fw"; : > "$fwres"

    unzip -Z1 "$jar" > "$names" 2>/dev/null || return 0
    [ -s "$names" ] || return 0

    grep -iE '^META-INF/jars/.+\.jar$' "$names" > "$nestedList" 2>/dev/null || true

    unzip -C -p "$jar" '*.class' '*.json' '*MANIFEST.MF*' >> "$content" 2>/dev/null || true

    local idx=0 entry njar
    while IFS= read -r entry; do
        [ -z "$entry" ] && continue
        idx=$((idx + 1))
        njar="$work/nested_$idx.jar"
        if unzip -p "$jar" "$entry" > "$njar" 2>/dev/null && [ -s "$njar" ]; then
            unzip -Z1 "$njar" >> "$names" 2>/dev/null || true
            unzip -C -p "$njar" '*.class' '*.json' '*MANIFEST.MF*' >> "$content" 2>/dev/null || true
        fi
        rm -f "$njar"
    done < "$nestedList"

    scan_patterns_to "$names" "$work/pat_names"
    scan_patterns_to "$content" "$work/pat_content"
    cat "$work/pat_names" "$work/pat_content" 2>/dev/null | LC_ALL=C sort -u > "$pats"

    scan_strings_to "$content" "$strs"

    # PowerShell: $Mod.Strings | Where-Object { $Mod.Patterns -notcontains $_ }
    if [ -s "$strs" ] && [ -s "$pats" ]; then
        LC_ALL=C grep -v -i -x -F -f "$pats" "$strs" > "$work/strs_filtered" 2>/dev/null || true
        mv "$work/strs_filtered" "$strs"
    fi

    scan_fullwidth_to "$content" "$fw"
    resolve_fullwidth_to "$fw" "$fwres"
}

# ---------------------------------------------------------------------------
# Pass 3 — bypass / injection scan
# ---------------------------------------------------------------------------
test_suspicious_jar_name() { # jar basename -> 0 if suspicious
    local base=$1 lower
    base=${base%.*}
    case "$base" in
        *[0-9]*) return 1 ;;
    esac
    lower=$(printf '%s' "$base" | tr '[:upper:]' '[:lower:]')
    case "$lower" in
        com_*|org_*|net_*|io_*|dev_*|gs_*|xyz_*|app_*|me_*|tv_*|uk_*|be_*|fr_*|de_*) return 1 ;;
    esac
    [ ${#base} -gt 20 ] && return 1
    return 0
}

bypass_scan() { # jar workdir -> writes workdir/flags
    local jar=$1 work=$2
    local names="$work/names" nestedList="$work/nested.list"
    local flagsFile="$work/flags"
    : > "$flagsFile"

    unzip -Z1 "$jar" > "$names" 2>/dev/null || return 0
    [ -s "$names" ] || return 0

    grep -iE '^META-INF/jars/.+\.jar$' "$names" > "$nestedList" 2>/dev/null || true

    local outerClasses nestedCount
    outerClasses=$(LC_ALL=C grep -icE '\.class$' "$names" 2>/dev/null || true)
    nestedCount=$(LC_ALL=C grep -icE '^META-INF/jars/.+\.jar$' "$names" 2>/dev/null || true)
    outerClasses=${outerClasses:-0}
    nestedCount=${nestedCount:-0}

    mkdir -p "$work/classes/outer"
    unzip -C -o -q "$jar" '*.class' -d "$work/classes/outer" 2>/dev/null || true

    local idx=0 entry njar
    while IFS= read -r entry; do
        [ -z "$entry" ] && continue
        idx=$((idx + 1))
        njar="$work/inner_$idx.jar"
        if unzip -p "$jar" "$entry" > "$njar" 2>/dev/null && [ -s "$njar" ]; then
            unzip -Z1 "$njar" >> "$names" 2>/dev/null || true
            mkdir -p "$work/classes/inner_$idx"
            unzip -C -o -q "$njar" '*.class' -d "$work/classes/inner_$idx" 2>/dev/null || true
        fi
        rm -f "$njar"
    done < "$nestedList"

    # Suspicious nested JAR names
    local nested base
    while IFS= read -r nested; do
        [ -z "$nested" ] && continue
        base=${nested##*/}
        if test_suspicious_jar_name "$base"; then
            printf 'Suspicious nested JAR — no version, unknown dependency: %s\n' "$base" >> "$flagsFile"
        fi
    done < "$nestedList"

    # Hollow shell
    if [ "$nestedCount" -eq 1 ] && [ "$outerClasses" -lt 3 ]; then
        local njName
        njName=$(head -n 1 "$nestedList")
        njName=${njName##*/}
        printf 'Hollow shell — only %s own class(es), wraps: %s\n' "$outerClasses" "$njName" >> "$flagsFile"
    fi

    # Outer mod id (fake identity check)
    local outerModId="" fmj
    fmj=$(unzip -p "$jar" 'fabric.mod.json' 2>/dev/null || true)
    if [ -n "$fmj" ]; then
        outerModId=$(printf '%s' "$fmj" | json_key id)
    fi

    # Class statistics + dangerous code signatures
    local metrics bTotal=0 bNum=0 bUni=0 bObf=0 bObfPct=0 bNumPct=0 bUniPct=0
    local bRuntime=0 bDownload=0 bExfil=0
    metrics=$(perl "$SCAN_PL" bypass "$work/classes" "$names" 2>/dev/null)
    local k v
    while IFS='=' read -r k v; do
        case "$k" in
            total)      bTotal=$v ;;
            numeric)    bNum=$v ;;
            unicode)    bUni=$v ;;
            obfuscated) bObf=$v ;;
            obfpct)     bObfPct=$v ;;
            numpct)     bNumPct=$v ;;
            unipct)     bUniPct=$v ;;
            runtime)    bRuntime=$v ;;
            download)   bDownload=$v ;;
            exfil)      bExfil=$v ;;
        esac
    done <<< "$metrics"

    if [ "$bRuntime" = "1" ] && [ "$bObfPct" -ge 25 ]; then
        printf 'Runtime.exec() in obfuscated code — can run arbitrary OS commands\n' >> "$flagsFile"
    fi
    if [ "$bDownload" = "1" ]; then
        printf 'HTTP file download — fetches and writes files from a remote server at runtime\n' >> "$flagsFile"
    fi
    if [ "$bExfil" = "1" ]; then
        printf 'HTTP POST exfiltration — sends system data to an external server\n' >> "$flagsFile"
    fi
    if [ "$bTotal" -ge 10 ] && [ "$bObfPct" -ge 25 ]; then
        printf 'Heavy obfuscation — %s%% of classes use single-letter path segments (a/b/c style)\n' "$bObfPct" >> "$flagsFile"
    fi
    if [ "$bNumPct" -ge 20 ]; then
        printf 'Numeric class names — %s%% of classes have numeric-only names (e.g. 1234.class)\n' "$bNumPct" >> "$flagsFile"
    fi
    if [ "$bUniPct" -ge 10 ]; then
        printf 'Unicode class names — %s%% of classes use non-ASCII characters\n' "$bUniPct" >> "$flagsFile"
    fi

    local knownLegitModIds=(
        "vmp-fabric" "vmp" "lithium" "sodium" "iris" "fabric-api"
        "modmenu" "ferrite-core" "lazydfu" "starlight" "entityculling"
        "memoryleakfix" "krypton" "c2me-fabric" "smoothboot-fabric"
        "immediatelyfast" "noisium" "threadtweak"
    )
    local dangerCount=0 line
    while IFS= read -r line; do
        case "$line" in
            *"Runtime.exec"*|*"HTTP file download"*|*"HTTP POST"*|*"Heavy obfuscation"*|*"Suspicious nested JAR"*)
                dangerCount=$((dangerCount + 1))
                ;;
        esac
    done < "$flagsFile"

    if [ -n "$outerModId" ] && in_list "$outerModId" "${knownLegitModIds[@]}" && [ "$dangerCount" -gt 0 ]; then
        printf "Fake mod identity — claims to be '%s' but contains dangerous code\n" "$outerModId" >> "$flagsFile"
    fi
}

# ---------------------------------------------------------------------------
# Pass 4 — obfuscation analysis
# ---------------------------------------------------------------------------
obf_scan() { # jar workdir -> writes workdir/flags
    local jar=$1 work=$2
    local flagsFile="$work/flags"
    : > "$flagsFile"

    unzip -Z1 "$jar" 2>/dev/null | LC_ALL=C grep -iE '\.class$' > "$work/classnames" || true
    [ -s "$work/classnames" ] || return 0

    mkdir -p "$work/classes"
    unzip -C -o -q "$jar" '*.class' -d "$work/classes" 2>/dev/null || true

    local metrics oTotal=0 oNum=0 oUni=0 oFw=0 oJp=0 oSingle=0 oTwo=0
    local oGib=0 oNov=0 oConf=0 oSinglePkg=0 oFwCount=0 oExamples=""
    metrics=$(perl "$SCAN_PL" obf "$work/classes" "$work/classnames" 2>/dev/null)
    local k v obfName obfPat
    while IFS='=' read -r k v; do
        case "$k" in
            total)      oTotal=$v ;;
            numeric)    oNum=$v ;;
            unicode)    oUni=$v ;;
            fullwidth)  oFw=$v ;;
            japanese)   oJp=$v ;;
            single)     oSingle=$v ;;
            two)        oTwo=$v ;;
            gibberish)  oGib=$v ;;
            novowel)    oNov=$v ;;
            confusion)  oConf=$v ;;
            singlepkg)  oSinglePkg=$v ;;
            fwcount)    oFwCount=$v ;;
            fwexamples) oExamples=$v ;;
            obfmatch)
                obfName=${v%%$'\t'*}
                obfPat=${v#*$'\t'}
                printf 'Known cheat obfuscator detected — %s (matched: %s)\n' "$obfName" "$obfPat" >> "$flagsFile"
                ;;
        esac
    done <<< "$metrics"

    [ "$oTotal" -lt 5 ] && return 0

    local pctNum pctUni pctFw pctJp pctS1 pctS2 pctGib pctNov pctConf
    pctNum=$(sprintf_pct "$oNum" "$oTotal")
    pctUni=$(sprintf_pct "$oUni" "$oTotal")
    pctFw=$(sprintf_pct "$oFw" "$oTotal")
    pctJp=$(sprintf_pct "$oJp" "$oTotal")
    pctS1=$(sprintf_pct "$oSingle" "$oTotal")
    pctS2=$(sprintf_pct "$oTwo" "$oTotal")
    pctGib=$(sprintf_pct "$oGib" "$oTotal")
    pctNov=$(sprintf_pct "$oNov" "$oTotal")
    pctConf=$(sprintf_pct "$oConf" "$oTotal")

    [ "$pctNum" -ge 20 ] && printf 'Numeric class names — %s%% of classes have numeric-only names\n' "$pctNum" >> "$flagsFile"
    [ "$pctUni" -ge 10 ] && printf 'Unicode class names — %s%% of classes use non-ASCII characters\n' "$pctUni" >> "$flagsFile"
    [ "$pctFw" -gt 0 ]   && printf 'Fullwidth Unicode class names — %s%% use ａｂｃ/ＡＢＣ/０１２ chars (%s classes)\n' "$pctFw" "$oFw" >> "$flagsFile"
    [ "$pctJp" -gt 0 ]   && printf 'Japanese obfuscation — %s%% use hiragana/katakana class names (%s classes)\n' "$pctJp" "$oJp" >> "$flagsFile"
    [ "$pctS1" -ge 15 ]  && printf 'Single-letter class names — %s%% (%s classes)\n' "$pctS1" "$oSingle" >> "$flagsFile"
    [ "$pctS2" -ge 20 ]  && printf 'Two-letter class names — %s%% (%s classes)\n' "$pctS2" "$oTwo" >> "$flagsFile"
    [ "$pctGib" -ge 5 ]  && printf 'Gibberish class names — %s%% have no vowels / consonant clusters (%s classes)\n' "$pctGib" "$oGib" >> "$flagsFile"
    [ "$pctNov" -ge 8 ]  && printf 'No-vowel class names — %s%% (%s classes)\n' "$pctNov" "$oNov" >> "$flagsFile"
    [ "$pctConf" -ge 3 ] && printf 'Confusion-char names (Il1O0/_) — %s%% (%s classes)\n' "$pctConf" "$oConf" >> "$flagsFile"
    [ "$oSinglePkg" -ge 6 ] && printf 'Single-char package paths — %s path segments like a/b/c\n' "$oSinglePkg" >> "$flagsFile"

    if [ "$oFwCount" -gt 0 ]; then
        printf 'Fullwidth strings in class content — %s occurrences (e.g. %s)\n' "$oFwCount" "$oExamples" >> "$flagsFile"
    fi
}

sprintf_pct() { # n total
    perl -e 'printf "%.0f", ($ARGV[0] / $ARGV[1]) * 100' "$1" "$2" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Pass 5 — JVM / runtime injection scan
# ---------------------------------------------------------------------------
jvm_scan() {
    jvmFlags=()
    [ -n "$JAVA_PID" ] || return 0

    local cmdline
    cmdline=$(process_cmdline "$JAVA_PID")
    [ -z "$cmdline" ] && return 0

    local raw agentPath agentName
    while IFS= read -r raw; do
        [ -z "$raw" ] && continue
        agentPath=${raw//\"/}
        agentPath=${agentPath//\'/}
        agentName=${agentPath##*/}
        agentName=${agentName##*\\}
        if ! printf '%s' "$agentName" | grep -qiE 'jmxremote|yjp|jrebel|newrelic|jacoco|theseus'; then
            jvmFlags+=("JVM Agent — -javaagent:$agentName (path: $agentPath)")
        fi
    done < <(printf '%s\n' "$cmdline" | grep -oE -- '-javaagent:[^[:space:]"]+' 2>/dev/null | sed 's/^-javaagent://')

    local flags=(
        "-Xbootclasspath/p:|prepends to bootstrap classpath, overrides core Java classes"
        "-Xbootclasspath/a:|appends to bootstrap classpath, injects below classloader"
        "-agentlib:jdwp|JDWP debug agent, remote debugging enabled"
        "-agentpath:|native agent loaded, bypasses Java sandbox"
    )
    local pair flag desc
    for pair in "${flags[@]}"; do
        flag=${pair%%|*}
        desc=${pair#*|}
        if printf '%s' "$cmdline" | grep -Fqi -- "$flag"; then
            jvmFlags+=("Suspicious JVM flag — $flag ($desc)")
        fi
    done
}

# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------
write_suspicious_card() {
    local file=$1 patterns=$2 strings=$3 fullwidth=$4 line

    printf '%s  %s%s\n' "$C_DARKRED" "$(repeat_char "─" 70)" "$C_RESET"
    printf '%s  │ %s%s FLAGGED %s  %s%s%s\n' \
        "$C_DARKRED" "$C_RESET" "${C_WHITE}${C_BG_DARKRED}" "$C_RESET" "$C_YELLOW" "$file" "$C_RESET"
    printf '%s  │ %s%s\n' "$C_DARKRED" "$(repeat_char "─" 66)" "$C_RESET"

    if [ -n "$patterns" ]; then
        printf '%s  │%s\n' "$C_DARKRED" "$C_RESET"
        printf '%s  │  %s%sPATTERNS%s\n' "$C_DARKRED" "$C_RESET" "$C_DARKGRAY" "$C_RESET"
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            printf '%s  │    %s%s%s%s\n' "$C_DARKRED" "$C_RESET" "$C_RED" "$line" "$C_RESET"
        done <<< "$patterns"
    fi

    if [ -n "$strings" ]; then
        printf '%s  │%s\n' "$C_DARKRED" "$C_RESET"
        printf '%s  │  %s%sSTRINGS%s\n' "$C_DARKRED" "$C_RESET" "$C_DARKGRAY" "$C_RESET"
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            printf '%s  │    %s%s%s%s\n' "$C_DARKRED" "$C_RESET" "$C_DARKYELLOW" "$line" "$C_RESET"
        done <<< "$strings"
    fi

    if [ -n "$fullwidth" ]; then
        printf '%s  │%s\n' "$C_DARKRED" "$C_RESET"
        printf '%s  │  %s%sFULLWIDTH UNICODE%s\n' "$C_DARKRED" "$C_RESET" "$C_DARKGRAY" "$C_RESET"
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            printf '%s  │    %s%sFULLWIDTH: %s%s\n' "$C_DARKRED" "$C_RESET" "$C_CYAN" "$line" "$C_RESET"
        done <<< "$fullwidth"
    fi

    printf '%s  │%s\n' "$C_DARKRED" "$C_RESET"
    printf '%s  %s%s\n\n' "$C_DARKRED" "$(repeat_char "─" 70)" "$C_RESET"
}

write_flag_card() { # file flags badge bullet bgcolor
    local file=$1 flags=$2 badge=$3 bullet=$4 bg=$5 line title desc
    printf '%s  %s%s\n' "$C_DARKMAGENTA" "$(repeat_char "─" 70)" "$C_RESET"
    printf '%s  │ %s%s %s %s  %s%s%s\n' \
        "$C_DARKMAGENTA" "$C_RESET" "${C_WHITE}${bg}" "$badge" "$C_RESET" "$C_YELLOW" "$file" "$C_RESET"
    printf '%s  │ %s%s\n' "$C_DARKMAGENTA" "$(repeat_char "─" 66)" "$C_RESET"

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        if [[ $line == *" — "* ]]; then
            title=${line%% — *}
            desc=${line#* — }
        else
            title=$line
            desc=""
        fi
        printf '%s  │%s\n' "$C_DARKMAGENTA" "$C_RESET"
        printf '%s  │  %s%s%s %s%s%s\n' \
            "$C_DARKMAGENTA" "$C_RESET" "$C_MAGENTA" "$bullet" "$C_WHITE" "$title" "$C_RESET"
        if [ -n "$desc" ]; then
            printf '%s  │    %s%s%s%s\n' "$C_DARKMAGENTA" "$C_RESET" "$C_GRAY" "$desc" "$C_RESET"
        fi
    done <<< "$flags"

    printf '%s  │%s\n' "$C_DARKMAGENTA" "$C_RESET"
    printf '%s  %s%s\n\n' "$C_DARKMAGENTA" "$(repeat_char "─" 70)" "$C_RESET"
}

# ---------------------------------------------------------------------------
# PASS 1 — hash verification
# ---------------------------------------------------------------------------
spinnerFrames=("⣾" "⣽" "⣻" "⢿" "⡿" "⣟" "⣯" "⣷")

printf '%s🔍 Pass 1 — Hash verification (Modrinth + Megabase)...%s\n' "$C_CYAN" "$C_RESET"

modrinthWhitelistedSlugs=("viafabricplus" "viafabricversion")

idx=0
for jar in "${jarFiles[@]}"; do
    idx=$((idx + 1))
    filename=$(basename "$jar")
    spinner="${spinnerFrames[$((idx % ${#spinnerFrames[@]}))]}"
    printf '\r%s[%s] Verifying: %s/%s - %s%s' "$C_YELLOW" "$spinner" "$idx" "$totalFiles" "$filename" "$C_RESET"

    hash=$(file_sha1 "$jar")
    if [ -n "$hash" ]; then
        modrinthRes=$(query_modrinth "$hash")
        mName=${modrinthRes%%|*}
        mSlug=${modrinthRes#*|}

        if [ -n "$mSlug" ]; then
            mSlugLower=$(printf '%s' "$mSlug" | tr '[:upper:]' '[:lower:]')
            isWhitelisted="false"
            for ws in "${modrinthWhitelistedSlugs[@]}"; do
                [ "$mSlugLower" = "$ws" ] && isWhitelisted="true"
            done
            verifiedNames+=("$mName")
            verifiedFiles+=("$filename")
            verifiedPaths+=("$jar")
            verifiedWhite+=("$isWhitelisted")
            continue
        fi

        megaName=$(query_megabase "$hash")
        if [ -n "$megaName" ]; then
            verifiedNames+=("$megaName")
            verifiedFiles+=("$filename")
            verifiedPaths+=("$jar")
            verifiedWhite+=("false")
            continue
        fi
    fi

    src=$(get_download_source "$jar")
    unknownFiles+=("$filename")
    unknownSources+=("$src")
    unknownPaths+=("$jar")
done
printf '\r%*s\r' 100 ''

# ---------------------------------------------------------------------------
# PASS 2 — deep scan
# ---------------------------------------------------------------------------
printf '%s🔬 Pass 2 — Deep-scanning all %s %s...%s\n' "$C_CYAN" "$totalFiles" "$modWord" "$C_RESET"

SCAN_WORK="$TMPROOT/work"
idx=0
for jar in "${jarFiles[@]}"; do
    idx=$((idx + 1))
    filename=$(basename "$jar")
    spinner="${spinnerFrames[$((idx % ${#spinnerFrames[@]}))]}"
    printf '\r%s[%s] Scanning: %s/%s - %s%s' "$C_YELLOW" "$spinner" "$idx" "$totalFiles" "$filename" "$C_RESET"

    if is_modrinth_whitelisted "$filename"; then
        continue
    fi

    rm -rf "$SCAN_WORK"
    mkdir -p "$SCAN_WORK"

    deep_scan "$jar" "$SCAN_WORK"

    if [ -s "$SCAN_WORK/pats" ] || [ -s "$SCAN_WORK/strs" ] || [ -s "$SCAN_WORK/fwres" ]; then
        suspFiles+=("$filename")
        suspPatterns+=("$(cat "$SCAN_WORK/pats" 2>/dev/null)")
        suspStrings+=("$(cat "$SCAN_WORK/strs" 2>/dev/null)")
        suspFullwidth+=("$(cat "$SCAN_WORK/fwres" 2>/dev/null)")
        suspPaths+=("$jar")
        remove_verified "$filename"
    fi
done
printf '\r%*s\r' 100 ''

# ---------------------------------------------------------------------------
# PASS 3 — bypass / injection
# ---------------------------------------------------------------------------
printf '%s🛡️  Pass 3 — Bypass/injection scan on all %s %s...%s\n' "$C_MAGENTA" "$totalFiles" "$modWord" "$C_RESET"

idx=0
for jar in "${jarFiles[@]}"; do
    idx=$((idx + 1))
    filename=$(basename "$jar")
    spinner="${spinnerFrames[$((idx % ${#spinnerFrames[@]}))]}"
    printf '\r%s[%s] Bypass scan: %s/%s - %s%s' "$C_YELLOW" "$spinner" "$idx" "$totalFiles" "$filename" "$C_RESET"

    if is_modrinth_whitelisted "$filename"; then
        continue
    fi

    rm -rf "$SCAN_WORK"
    mkdir -p "$SCAN_WORK"

    bypass_scan "$jar" "$SCAN_WORK"

    if [ -s "$SCAN_WORK/flags" ]; then
        bypassFiles+=("$filename")
        bypassFlags+=("$(cat "$SCAN_WORK/flags" 2>/dev/null)")
        bypassPaths+=("$jar")
        remove_verified "$filename"
        remove_unknown "$filename"
    fi
done
printf '\r%*s\r' 100 ''

# ---------------------------------------------------------------------------
# PASS 4 — obfuscation
# ---------------------------------------------------------------------------
printf '%s🔎 Pass 4 — Obfuscation analysis on all %s %s...%s\n' "$C_DARKCYAN" "$totalFiles" "$modWord" "$C_RESET"

idx=0
for jar in "${jarFiles[@]}"; do
    idx=$((idx + 1))
    filename=$(basename "$jar")
    spinner="${spinnerFrames[$((idx % ${#spinnerFrames[@]}))]}"
    printf '\r%s[%s] Obf scan: %s/%s - %s%s' "$C_YELLOW" "$spinner" "$idx" "$totalFiles" "$filename" "$C_RESET"

    rm -rf "$SCAN_WORK"
    mkdir -p "$SCAN_WORK"

    obf_scan "$jar" "$SCAN_WORK"

    if [ -s "$SCAN_WORK/flags" ]; then
        alreadyFlagged="false"
        in_list "$filename" "${suspFiles[@]}" && alreadyFlagged="true"
        in_list "$filename" "${bypassFiles[@]}" && alreadyFlagged="true"
        if [ "$alreadyFlagged" = "false" ]; then
            obfFiles+=("$filename")
            obfFlags+=("$(cat "$SCAN_WORK/flags" 2>/dev/null)")
            obfPaths+=("$jar")
            remove_verified "$filename"
        fi
    fi
done
printf '\r%*s\r' 100 ''

# ---------------------------------------------------------------------------
# PASS 5 — JVM
# ---------------------------------------------------------------------------
printf '%s⚡ Pass 5 — Scanning JVM for agents and injections...%s\n' "$C_DARKYELLOW" "$C_RESET"
JAVA_PID=$(find_java_pid)
jvm_scan
if [ ${#jvmFlags[@]} -gt 0 ]; then
    printf '%s   ⚠️  JVM issues found!%s\n' "$C_YELLOW" "$C_RESET"
else
    printf '%s   ✓  JVM looks clean%s\n' "$C_DARKGRAY" "$C_RESET"
fi
printf '\r%*s\r' 100 ''

# ---------------------------------------------------------------------------
# Output: verified
# ---------------------------------------------------------------------------
if [ ${#verifiedFiles[@]} -gt 0 ]; then
    write_section_header "VERIFIED MODS" "${#verifiedFiles[@]}" "$C_GREEN" "$C_GREEN"
    write_rule "─" 76 "$C_DARKGRAY"
    for ((i = 0; i < ${#verifiedFiles[@]}; i++)); do
        printf '  %s✓ %s%s%s%s → %s%s%s\n' \
            "$C_GREEN" "${C_RESET}${C_WHITE}" "${verifiedNames[i]}" "$C_RESET" \
            "$C_GRAY" "$C_DARKGRAY" "$(result_label "${verifiedFiles[i]}" "${verifiedPaths[i]}")" "$C_RESET"
    done
    printf '\n'
fi

# ---------------------------------------------------------------------------
# Output: unknown
# ---------------------------------------------------------------------------
if [ ${#unknownFiles[@]} -gt 0 ]; then
    write_section_header "UNKNOWN MODS" "${#unknownFiles[@]}" "$C_YELLOW" "$C_YELLOW"
    write_rule "─" 76 "$C_DARKGRAY"
    for ((i = 0; i < ${#unknownFiles[@]}; i++)); do
        name="${unknownFiles[i]}"
        if [ ${#name} -gt 50 ]; then
            name="${name:0:47}..."
        fi
        sourceText="${unknownSources[i]}"
        if [ -n "$sourceText" ]; then
            sourceText="Source: $sourceText"
        else
            sourceText="Source: ?"
        fi
        topLine="  ╔═ ? $name $(repeat_char "═" $((65 - ${#name})))╗"
        bottomLine="  ╚═ $sourceText $(repeat_char "═" $((67 - ${#sourceText})))╝"
        printf '%s%s%s\n' "$C_YELLOW" "$topLine" "$C_RESET"
        printf '%s%s%s\n' "$C_YELLOW" "$bottomLine" "$C_RESET"
        case "$scanMode" in
            system|launchers)
                printf '  %s↳ %s%s\n' "$C_DARKGRAY" "$(result_label "${unknownFiles[i]}" "${unknownPaths[i]}")" "$C_RESET"
                ;;
        esac
        printf '\n'
    done
fi

# ---------------------------------------------------------------------------
# Output: suspicious
# ---------------------------------------------------------------------------
if [ ${#suspFiles[@]} -gt 0 ]; then
    write_section_header "SUSPICIOUS MODS" "${#suspFiles[@]}" "$C_RED" "$C_RED"
    write_rule "─" 76 "$C_DARKGRAY"
    printf '\n'
    for ((i = 0; i < ${#suspFiles[@]}; i++)); do
        write_suspicious_card "$(result_label "${suspFiles[i]}" "${suspPaths[i]}")" "${suspPatterns[i]}" "${suspStrings[i]}" "${suspFullwidth[i]}"
    done
fi

# ---------------------------------------------------------------------------
# Output: bypass / injection
# ---------------------------------------------------------------------------
if [ ${#bypassFiles[@]} -gt 0 ]; then
    write_section_header "BYPASS / INJECTION DETECTED" "${#bypassFiles[@]}" "$C_MAGENTA" "$C_MAGENTA"
    write_rule "─" 76 "$C_DARKGRAY"
    printf '\n'
    for ((i = 0; i < ${#bypassFiles[@]}; i++)); do
        write_flag_card "$(result_label "${bypassFiles[i]}" "${bypassPaths[i]}")" "${bypassFlags[i]}" "INJECTION" "◉" "$C_BG_DARKMAGENTA"
    done
fi

# ---------------------------------------------------------------------------
# Output: obfuscated
# ---------------------------------------------------------------------------
if [ ${#obfFiles[@]} -gt 0 ]; then
    write_section_header "OBFUSCATED MODS" "${#obfFiles[@]}" "$C_DARKYELLOW" "$C_YELLOW"
    write_rule "─" 76 "$C_DARKGRAY"
    printf '\n'
    for ((i = 0; i < ${#obfFiles[@]}; i++)); do
        # Obfuscation cards use DarkYellow framing and a flag bullet
        file=$(result_label "${obfFiles[i]}" "${obfPaths[i]}")
        flags="${obfFlags[i]}"
        printf '%s  %s%s\n' "$C_DARKYELLOW" "$(repeat_char "─" 70)" "$C_RESET"
        printf '%s  │ %s%s OBFUSCATED %s  %s%s%s\n' \
            "$C_DARKYELLOW" "$C_RESET" "${C_BLACK}${C_BG_DARKYELLOW}" "$C_RESET" "$C_YELLOW" "$file" "$C_RESET"
        printf '%s  │ %s%s\n' "$C_DARKYELLOW" "$(repeat_char "─" 66)" "$C_RESET"
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            if [[ $line == *" — "* ]]; then
                title=${line%% — *}
                desc=${line#* — }
            else
                title=$line
                desc=""
            fi
            printf '%s  │%s\n' "$C_DARKYELLOW" "$C_RESET"
            printf '%s  │  %s%s⚑ %s%s%s\n' \
                "$C_DARKYELLOW" "$C_RESET" "$C_YELLOW" "$C_WHITE" "$title" "$C_RESET"
            if [ -n "$desc" ]; then
                printf '%s  │    %s%s%s%s\n' "$C_DARKYELLOW" "$C_RESET" "$C_GRAY" "$desc" "$C_RESET"
            fi
        done <<< "$flags"
        printf '%s  │%s\n' "$C_DARKYELLOW" "$C_RESET"
        printf '%s  %s%s\n\n' "$C_DARKYELLOW" "$(repeat_char "─" 70)" "$C_RESET"
    done
fi

# ---------------------------------------------------------------------------
# Output: JVM
# ---------------------------------------------------------------------------
if [ ${#jvmFlags[@]} -gt 0 ]; then
    write_section_header "JVM / RUNTIME INJECTION" "${#jvmFlags[@]}" "$C_YELLOW" "$C_YELLOW"
    write_rule "─" 76 "$C_DARKGRAY"
    printf '\n'
    printf '%s  %s%s\n' "$C_DARKYELLOW" "$(repeat_char "─" 70)" "$C_RESET"
    printf '%s  │ %s%s JVM %s  %s  javaw / java process%s\n' \
        "$C_DARKYELLOW" "$C_RESET" "${C_BLACK}${C_BG_YELLOW}" "$C_RESET" "$C_YELLOW" "$C_RESET"
    printf '%s  │ %s%s\n' "$C_DARKYELLOW" "$(repeat_char "─" 66)" "$C_RESET"

    for flag in "${jvmFlags[@]}"; do
        title=${flag%% — *}
        rest=${flag#* — }
        desc=$rest
        fpath=""
        if [[ $rest == *' (path: '*')' ]]; then
            fpath=${rest##* (path: }
            fpath=${fpath%)}
            desc=${rest% (path: *}
        fi

        printf '%s  │%s\n' "$C_DARKYELLOW" "$C_RESET"
        printf '%s  │  %s%s◉ %s%s%s\n' \
            "$C_DARKYELLOW" "$C_RESET" "$C_YELLOW" "$C_WHITE" "$title" "$C_RESET"
        if [ -n "$desc" ]; then
            printf '%s  │    %s%s%s%s\n' "$C_DARKYELLOW" "$C_RESET" "$C_GRAY" "$desc" "$C_RESET"
        fi
        if [ -n "$fpath" ]; then
            display="$fpath"
            if [ ${#display} -gt 60 ]; then
                display="...${display: -57}"
            fi
            printf '%s  │    %s%s%s%s\n' "$C_DARKYELLOW" "$C_RESET" "$C_DARKGRAY" "$display" "$C_RESET"
        fi
    done
    printf '%s  │%s\n' "$C_DARKYELLOW" "$C_RESET"
    printf '%s  %s%s\n\n' "$C_DARKYELLOW" "$(repeat_char "─" 70)" "$C_RESET"
fi

# ---------------------------------------------------------------------------
# Results file
# ---------------------------------------------------------------------------
write_results_file() {
    local outdir outfile line i
    outdir="${HOME:-.}/ss"
    outfile="$outdir/MeowModResults.txt"

    if ! mkdir -p "$outdir" 2>/dev/null; then
        printf '%s⚠️  Could not create results folder: %s%s\n\n' "$C_YELLOW" "$outdir" "$C_RESET"
        return 1
    fi

    {
        printf 'Meow Mod Analyzer — Results\n'
        printf 'Generated: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
        printf 'Scan scope: %s\n' "$scanMode"
        printf 'Scanned: %s\n' "$scanWhere"
        printf '\nSUMMARY\n-------\n'
        printf 'Total files scanned: %s\n' "$totalFiles"
        printf 'Verified mods:       %s\n' "${#verifiedFiles[@]}"
        printf 'Unknown mods:        %s\n' "${#unknownFiles[@]}"
        printf 'Suspicious mods:     %s\n' "${#suspFiles[@]}"
        printf 'Bypass/Injected:     %s\n' "${#bypassFiles[@]}"
        printf 'Obfuscated mods:     %s\n' "${#obfFiles[@]}"
        printf 'JVM issues:          %s\n' "${#jvmFlags[@]}"

        if [ ${#verifiedFiles[@]} -gt 0 ]; then
            printf '\nVERIFIED MODS\n-------------\n'
            for ((i = 0; i < ${#verifiedFiles[@]}; i++)); do
                printf '✓ %s → %s\n' "${verifiedNames[i]}" "$(full_mod_path "${verifiedPaths[i]}")"
            done
        fi

        if [ ${#unknownFiles[@]} -gt 0 ]; then
            printf '\nUNKNOWN MODS\n------------\n'
            for ((i = 0; i < ${#unknownFiles[@]}; i++)); do
                printf '? %s\n' "$(full_mod_path "${unknownPaths[i]}")"
                printf '  Source: %s\n' "${unknownSources[i]:-?}"
            done
        fi

        if [ ${#suspFiles[@]} -gt 0 ]; then
            printf '\nSUSPICIOUS MODS\n---------------\n'
            for ((i = 0; i < ${#suspFiles[@]}; i++)); do
                printf '! %s\n' "$(full_mod_path "${suspPaths[i]}")"
                if [ -n "${suspPatterns[i]}" ]; then
                    printf '  Patterns:\n'
                    while IFS= read -r line; do
                        [ -n "$line" ] && printf '    %s\n' "$line"
                    done <<< "${suspPatterns[i]}"
                fi
                if [ -n "${suspStrings[i]}" ]; then
                    printf '  Strings:\n'
                    while IFS= read -r line; do
                        [ -n "$line" ] && printf '    %s\n' "$line"
                    done <<< "${suspStrings[i]}"
                fi
                if [ -n "${suspFullwidth[i]}" ]; then
                    printf '  Fullwidth Unicode:\n'
                    while IFS= read -r line; do
                        [ -n "$line" ] && printf '    %s\n' "$line"
                    done <<< "${suspFullwidth[i]}"
                fi
            done
        fi

        if [ ${#bypassFiles[@]} -gt 0 ]; then
            printf '\nBYPASS / INJECTION DETECTED\n---------------------------\n'
            for ((i = 0; i < ${#bypassFiles[@]}; i++)); do
                printf '! %s\n' "$(full_mod_path "${bypassPaths[i]}")"
                while IFS= read -r line; do
                    [ -n "$line" ] && printf '    %s\n' "$line"
                done <<< "${bypassFlags[i]}"
            done
        fi

        if [ ${#obfFiles[@]} -gt 0 ]; then
            printf '\nOBFUSCATED MODS\n---------------\n'
            for ((i = 0; i < ${#obfFiles[@]}; i++)); do
                printf '! %s\n' "$(full_mod_path "${obfPaths[i]}")"
                while IFS= read -r line; do
                    [ -n "$line" ] && printf '    %s\n' "$line"
                done <<< "${obfFlags[i]}"
            done
        fi

        if [ ${#jvmFlags[@]} -gt 0 ]; then
            printf '\nJVM / RUNTIME INJECTION\n-----------------------\n'
            for line in "${jvmFlags[@]}"; do
                [ -n "$line" ] && printf '◉ %s\n' "$line"
            done
        fi
    } > "$outfile" 2>/dev/null || {
        printf '%s⚠️  Could not write results file: %s%s\n\n' "$C_YELLOW" "$outfile" "$C_RESET"
        return 1
    }

    printf '%s📝 Results saved to: %s%s\n\n' "$C_GRAY" "$outfile" "$C_RESET"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '%s📊 SUMMARY%s\n' "$C_CYAN" "$C_RESET"
write_rule "━" 76 "$C_BLUE"
printf '%s  Total files scanned: %s%s%s\n' "$C_GRAY" "$C_WHITE" "$totalFiles" "$C_RESET"
printf '%s  Verified mods:       %s%s%s\n' "$C_GRAY" "$C_GREEN" "${#verifiedFiles[@]}" "$C_RESET"
printf '%s  Unknown mods:        %s%s%s\n' "$C_GRAY" "$C_YELLOW" "${#unknownFiles[@]}" "$C_RESET"
printf '%s  Suspicious mods:     %s%s%s\n' "$C_GRAY" "$C_RED" "${#suspFiles[@]}" "$C_RESET"
printf '%s  Bypass/Injected:     %s%s%s\n' "$C_GRAY" "$C_MAGENTA" "${#bypassFiles[@]}" "$C_RESET"
printf '%s  Obfuscated mods:     %s%s%s\n' "$C_GRAY" "$C_YELLOW" "${#obfFiles[@]}" "$C_RESET"
printf '%s  JVM issues:          %s%s%s\n' "$C_GRAY" "$C_YELLOW" "${#jvmFlags[@]}" "$C_RESET"
printf '\n'
write_rule "━" 76 "$C_BLUE"
printf '\n'
write_results_file
printf '%s  ✨ Analysis complete! Thanks for using Meow Mod Analyzer 🐱%s\n' "$C_CYAN" "$C_RESET"
printf '\n'
printf '%s  👤 Created by: %s' "$C_WHITE" "$C_RESET"
printf '%s🌟 %s' "$C_CYAN" "$C_RESET"
printf '%sTonynoh%s\n' "$C_CYAN" "$C_RESET"
printf '%s  📱 My Socials: %s' "$C_WHITE" "$C_RESET"
printf '%s💬 %s' "$C_BLUE" "$C_RESET"
printf '%sDiscord  : %s' "$C_BLUE" "$C_RESET"
printf '%stonyboy90_%s\n' "$C_BLUE" "$C_RESET"

printf '                 '
printf '%s🔗 %s' "$C_DARKGRAY" "$C_RESET"
printf '%sGitHub   : %s' "$C_DARKGRAY" "$C_RESET"
printf '%shttps://github.com/MeowTonynoh%s\n' "$C_DARKGRAY" "$C_RESET"
printf '                 '
printf '%s🎥 %s' "$C_RED" "$C_RESET"
printf '%sYouTube  : %s' "$C_RED" "$C_RESET"
printf '%stonynoh-07%s\n' "$C_RED" "$C_RESET"
printf '\n'
write_rule "━" 76 "$C_BLUE"
printf '\n'
printf '%sPress any key to exit...%s\n' "$C_DARKGRAY" "$C_RESET"
IFS= read -r -n 1 -s
