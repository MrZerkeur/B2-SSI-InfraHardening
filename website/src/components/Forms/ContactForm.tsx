import { contact } from "@/app/actions";

export default function ContactForm() {
  return (
    <form action={contact} className="flex flex-col gap-4">
      <div className="flex flex-row gap-4">
        <label htmlFor="firstName">Prénom *</label>
        <input type="text" name="firstName" id="firstName" placeholder="Prénom..." required/>
      </div>
      <div className="flex flex-row gap-4">
        <label htmlFor="lastName">Nom de famille *</label>
        <input type="text" name="lastName" id="lastName" placeholder="Nom..." required/>
      </div>
      <div className="flex flex-row gap-4">
        <label htmlFor="email">Adresse mail *</label>
        <input type="email" name="email" id="email" placeholder="Adresse mail..." required/>
      </div>
      <div className="flex flex-row gap-4">
        <label htmlFor="tel">Numéro de téléphone</label>
        <input type="tel" name="tel" id="tel" />
      </div>
      <div className="flex flex-row gap-4">
      <label htmlFor="message">Message *</label>
        <input type="text" name="message" id="message" placeholder="Ecrire message" required/>
      </div>
      <div className="flex flex-row gap-4">
        <label htmlFor="file">Image (optionnelle)</label>
        <input type="file" name="file" id="file" accept="image/*"/>
      </div>
      <button className="text-white">Envoyer</button>
    </form>
  )
}