package main

import (
	"fmt"
	"os"
	"strings"
)

// A dark, terminal-first palette: near-black canvas with soft accents.
const (
	cReset  = "\x1b[0m"
	cBold   = "\x1b[1m"
	cFg     = "\x1b[38;2;228;228;231m"
	cDim    = "\x1b[38;2;113;113;122m"
	cCyan   = "\x1b[38;2;94;234;212m"
	cBlue   = "\x1b[38;2;125;211;252m"
	cPurple = "\x1b[38;2;167;139;250m"
	cGreen  = "\x1b[38;2;134;239;172m"
	cRed    = "\x1b[38;2;248;113;113m"
	cYellow = "\x1b[38;2;253;230;138m"
	bgSeq   = "\x1b[48;2;9;9;11m"
)

var colorOn = colorRequested()

func colorRequested() bool {
	if os.Getenv("NO_COLOR") != "" || strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}
	if isTerminal() {
		return true
	}
	return os.Getenv("FORCE_COLOR") != "" || os.Getenv("CLICOLOR_FORCE") != ""
}

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// paint applies a style and restores the themed foreground/background so the
// dark canvas survives every reset sequence.
func paint(style, s string) string {
	if !colorOn || style == "" || s == "" {
		return s
	}
	return style + s + cReset + bgSeq + cFg
}

func enterTheme() {
	enableANSI()
	if !colorOn {
		return
	}
	// Ask the terminal itself to use a near-black canvas, then clear into it.
	fmt.Print("\x1b]11;#09090b\x07")
	fmt.Print(bgSeq + cFg + "\x1b[2J\x1b[H")
}

func exitTheme() {
	if !colorOn {
		return
	}
	fmt.Print(cReset + "\x1b]111\x07\x1b[?25h")
}

var bannerLines = []string{
	"",
	"                      ••••",
	"      ••••••••••••••• ••••        ••••••••••",
	"    •••  ••• •••• ••• •••••••   ••• •••• ••••   • ",
	"   •••• •••• ••••••••  ••••••  •••  •••  •••••••••",
	"    •••••••      •••     •••• ••••  •••  ••••  •••",
	"                ••••     •••  •••• •••• ••••",
	"                •••     ••••  ••••••••••••",
	"               ••••     ••••",
	"                ••",
	"      NETWORK INTELLIGENCE TOOLKIT  /  Go",
	"",
}

// gradient sweeps the banner from mint to violet.
func gradient(i, n int) string {
	t := 0.0
	if n > 1 {
		t = float64(i) / float64(n-1)
	}
	r := int(94 + (167-94)*t)
	g := int(234 + (139-234)*t)
	b := int(212 + (250-212)*t)
	return fmt.Sprintf("\x1b[38;2;%d;%d;%dm", r, g, b)
}

func renderBanner() {
	for i, line := range bannerLines {
		style := gradient(i, len(bannerLines))
		if strings.Contains(line, "TOOLKIT") {
			style += cBold
		}
		fmt.Println(paint(style, line))
	}
}

var menuItems = [][2]string{
	{"1", "WHOIS / RDAP"}, {"2", "DNS"}, {"3", "IP"},
	{"4", "SSL / TLS"}, {"5", "HTTP"}, {"6", "PORTS"},
	{"7", "Subdomains"}, {"8", "Health"}, {"9", "Threat"},
}

func renderMenu() {
	fmt.Println()
	fmt.Println("  " + paint(cPurple, "▐ ") + paint(cBold+cFg, "SELECT A MODULE"))
	fmt.Println("  " + paint(cDim, strings.Repeat("─", 58)))
	for i := 0; i < len(menuItems); i += 3 {
		var b strings.Builder
		b.WriteString("  ")
		for _, it := range menuItems[i:min(i+3, len(menuItems))] {
			b.WriteString(paint(cCyan+cBold, "["+it[0]+"]"))
			b.WriteString(" ")
			b.WriteString(paint(cFg, fmt.Sprintf("%-17s", it[1])))
		}
		fmt.Println(b.String())
	}
	fmt.Println("  " + paint(cCyan+cBold, "[0]") + " " + paint(cDim, "Exit"))
	fmt.Println("  " + paint(cDim, strings.Repeat("─", 58)))
}
