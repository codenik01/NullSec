#!/bin/bash
# ns-sandbox / ns-lab isolation tests, each with a POSITIVE control (so a refusal can't masquerade as a pass).
BIN=$(cd "$(dirname "$0")/../overlay/usr/local/bin" && pwd); export PATH=$BIN:$PATH
if ! ns-sandbox -- true 2>/dev/null; then echo "SKIP  bubblewrap cannot create a sandbox here (userns restricted?)"; exit 0; fi
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/home/.ssh" "$T/work"; echo PRIVATE-KEY-DATA > "$T/home/.ssh/id_ed25519"; echo hello > "$T/work/sample.txt"
export HOME=$T/home AWS_SECRET_ACCESS_KEY=topsecret123
f=0; t(){ if bash -c "$2" >/tmp/sb.out 2>&1; then echo "PASS  $1"; else echo "FAIL  $1"; head -5 /tmp/sb.out | sed 's/^/        /'; f=$((f+1)); fi; }
t "runs a command (builtin-named echo)"       'ns-sandbox -- echo inside | grep -q inside'
t "POSITIVE: reads system files"              'ns-sandbox -- cat /etc/passwd | grep -q root'
t "same sandbox cannot read ~/.ssh key"       "ns-sandbox -- sh -c 'cat $T/home/.ssh/id_ed25519; echo ran' | grep -q ran && ! ns-sandbox -- cat $T/home/.ssh/id_ed25519 | grep -q PRIVATE"
t "AWS secret env var not inherited"          'ns-sandbox -- sh -c "echo ran; env" | grep -q ran && ! ns-sandbox -- env | grep -q topsecret123'
t "only loopback network by default"          '[ "$(ns-sandbox -- sh -c "tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d \" \"")" = lo ]'
t "--ro readable not writable"                "ns-sandbox --ro $T/work -- cat $T/work/sample.txt | grep -q hello && ! ns-sandbox --ro $T/work -- sh -c 'echo x > $T/work/z'"
t "--rw writable"                             "ns-sandbox --rw $T/work -- sh -c 'echo y > $T/work/n' && grep -q y $T/work/n"
t "refuses to bind / and /etc"                '! ns-sandbox --ro / -- true && ! ns-sandbox --rw /etc -- true'
t "REFUSES (rc 125) when bwrap missing"       'PATH=/nonexistent /usr/bin/bash $(command -v ns-sandbox) -- true; [ $? -eq 125 ]'
t "unknown command -> 127, not run"           'ns-sandbox -- nonexistentcmd; [ $? -eq 127 ]'
echo "echo data > $T/s.bin" | bash
t "analyze: copy visible, original hidden"    "out=\$(printf 'ls $T/s.bin 2>&1; cat /tmp/tmp.*/sample; exit\n' | ns-lab analyze $T/s.bin 2>&1); echo \"\$out\" | grep -q 'No such file' && echo \"\$out\" | grep -q '^data'"
t "workspace: discarded on exit"              "printf 'touch ~/x; exit\n' | ns-lab workspace >/dev/null 2>&1; [ ! -e $T/home/x ]"
t "ns-pack profiles (offline)"                "sed 's#/usr/share/nullsec#$BIN/../../share/nullsec#g' $BIN/ns-pack > $T/nspack && bash $T/nspack profiles | grep -q '^network'"
t "ns-pack info (offline)"                    "bash $T/nspack info nmap | grep -q 'category:  recon'"
[ $f -eq 0 ] && echo "SANDBOX: ALL PASSED" || echo "SANDBOX: $f FAILED"; exit $f
