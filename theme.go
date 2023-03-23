package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

type AppTheme struct{}

var _ fyne.Theme = (*AppTheme)(nil)

func (appTheme AppTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	//if name == theme.ColorNameBackground {
	//	return color.NRGBA{R: 0x1c, G: 0x1c, B: 0x1c, A: 0xFF}
	//}
	//if name == theme.ColorNameButton {
	//	return color.NRGBA{R: 0x47, G: 0x2C, B: 0x4C, A: 0xFF}
	//}
	return theme.DefaultTheme().Color(name, variant)
}

func (appTheme AppTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}
func (appTheme AppTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}
func (appTheme AppTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name)
}
