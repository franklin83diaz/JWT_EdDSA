package main

import (
	"JWT_EdDSA/pkg"
	"log"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

func main() {
	a := app.New()
	w := a.NewWindow("JWT EDDSA")

	w.Resize(fyne.NewSize(600, 570))

	inputEnc := widget.NewEntry()
	inputEnc.SetPlaceHolder("encode JWT...")
	inputEnc.MultiLine = true

	inputDEc := widget.NewEntry()
	inputDEc.SetPlaceHolder("decode body JWT...")
	inputDEc.MultiLine = true

	inputDEc.Wrapping = fyne.TextWrapWord
	inputDEc.SetMinRowsVisible(10)
	inputDEc.Wrapping = fyne.TextWrapWord
	inputDEc.SetMinRowsVisible(10)

	privPEM := widget.NewEntry()
	privPEM.SetPlaceHolder("private...")

	pubPEM := widget.NewEntry()
	pubPEM.SetPlaceHolder("public...")

	w.SetContent(container.NewVBox(
		widget.NewLabel("JWT EDDSA ENCODE"),
		inputEnc,
		widget.NewLabel("JWT EDDSA DECODE"),
		inputDEc,
		container.NewHBox(
			widget.NewLabel("PKCS8:"),
			layout.NewSpacer(),
			widget.NewButton("Generate Keys", func() {
				pub, priv, err := pkg.GenerateKeyPair()
				if err != nil {
					log.Println("Error generating key pair:", err)
				} else {
					pubPEM.SetText(pub)
					privPEM.SetText(priv)
				}
			}),
		),
		privPEM,
		pubPEM,
		widget.NewButton("Verify & Decode", func() {
			claims, err := pkg.Verify(inputEnc.Text, pubPEM.Text)

			if err != nil {
				log.Println("Error verifying JWT:", err)
				claims = "Error: " + err.Error()
			}
			inputDEc.Text = claims
			inputDEc.Refresh()
		}),
		widget.NewButton("Encode & Sign", func() {

			token, err := pkg.GenJWTFromJSON(inputDEc.Text, privPEM.Text)
			if err != nil {
				log.Println("Error generating JWT:", err)
				token = "Error: " + err.Error()
			}
			inputEnc.Text = token
			inputEnc.Refresh()

		}),
	))

	w.ShowAndRun()
}
