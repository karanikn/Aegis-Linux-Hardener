"""Terminal palettes (256 colors with 8-color fallback)."""
# bg, text, accent, selected bg, warning, good/installed, danger, muted, selected badge
PALETTES={
 'slate':(235,252,81,24,214,114,203,245,157),
 'blue':(234,255,39,25,220,117,203,245,159),
 'nord':(236,254,109,60,222,150,174,245,194),
 'dracula':(235,253,141,61,228,84,210,245,121),
 'gruvbox':(235,223,214,94,172,142,167,245,229),
 'solarized':(234,230,37,23,136,70,160,245,157),
 'forest':(233,252,78,22,220,114,203,244,193),
 'amber':(234,223,214,94,220,222,196,244,230),
 'light':(255,235,25,153,130,28,160,243,22),
 'plain':(0,7,6,4,3,2,1,7,2),
}


def valid(name):return name if name in PALETTES else 'slate'
