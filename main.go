package main

import (
	"JWT_EdDSA/pkg"
	"log"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func main() {
	a := app.New()
	w := a.NewWindow("JWT EDDSA")

	inputEnc := widget.NewEntry()
	inputEnc.SetPlaceHolder("encode JWT...")
	inputEnc.MultiLine = true

	inputDEc := widget.NewEntry()
	inputDEc.SetPlaceHolder("decode body JWT...")
	inputDEc.MultiLine = true
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
		widget.NewLabel("PEMS:"),
		privPEM,
		pubPEM,
		widget.NewButton("Check", func() {
			claims, err := pkg.VerifyJWT(inputEnc.Text, []byte(pkg.ParsePubPEM(pubPEM.Text)))
			if err != nil {
				log.Println("Error verifying JWT:", err)
				claims = "Error: " + err.Error()
			}
			inputDEc.Text = claims
			inputDEc.Refresh()
		}),
		widget.NewButton("Encode", func() {

			token, err := pkg.GenJWTFromJSON(inputDEc.Text, []byte(pkg.ParsePrivPEM(privPEM.Text)))
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
