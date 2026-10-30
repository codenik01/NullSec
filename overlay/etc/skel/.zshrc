HISTFILE=~/.zsh_history; HISTSIZE=50000; SAVEHIST=50000
setopt SHARE_HISTORY HIST_IGNORE_DUPS AUTO_CD PROMPT_SUBST
autoload -Uz compinit && compinit -d ~/.cache/zcompdump
zstyle ':completion:*' menu select
for f in /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh \
         /usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh \
         /usr/share/doc/fzf/examples/key-bindings.zsh; do [ -r $f ] && source $f; done

# prompt:  [ip] [target] user@host ~/path   (ip prefers tun0)
_ipp() {
  local i=$(ip -4 -o addr show tun0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
  [ -z "$i" ] && i=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
  echo "${i:--}"
}
_tgt() { [ -n "$TARGET" ] && printf '%%F{8}[%%f%%F{1}%s%%f%%F{8}]%%f ' "$TARGET"; }
PROMPT='%F{8}[%f%F{15}$(_ipp)%f%F{8}]%f $(_tgt)%F{15}%n%F{8}@%F{15}%m %F{8}%~%f
%(?.%F{1}.%F{9})>%f '

alias ls='ls --color=auto -lAh --group-directories-first'
alias grep='grep --color=auto'
alias ports='ss -tulpn'
alias myip='curl -s ifconfig.me; echo'
alias serve='python3 -m http.server 8000'
target()   { export TARGET="$1"; mkdir -p ~/ops/"$1"/{recon,loot,notes}; cd ~/ops/"$1"; }
untarget() { unset TARGET; cd ~; }
