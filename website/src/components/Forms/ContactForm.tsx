"use client"

import { contact } from "@/app/actions";
import { useFormState } from "react-dom";

export default function ContactForm() {

  const [state, formAction] = useFormState<any, FormData>(contact, undefined)

  return (
    <form action={formAction} className="flex flex-col justify-center items-center gap-2 w-1/2 h-[20rem] bg-gray-900 rounded-md">
      <div className="flex flex-row gap-4">
        <label htmlFor="firstName" className="text-white">Prénom *</label>
        <input type="text" name="firstName" id="firstName" placeholder="Prénom..." required/>
      </div>
      <div className="flex flex-row gap-4">
        <label htmlFor="lastName" className="text-white">Nom de famille *</label>
        <input type="text" name="lastName" id="lastName" placeholder="Nom..." required/>
      </div>
      <div className="flex flex-row gap-4">
        <label htmlFor="email" className="text-white">Adresse mail *</label>
        <input type="email" name="email" id="email" placeholder="Adresse mail..." required/>
      </div>
      <div className="flex flex-row gap-4">
        <label htmlFor="tel" className="text-white">Numéro de téléphone</label>
        <input type="tel" name="tel" id="tel" />
      </div>
      <div className="flex flex-row gap-4">
      <label htmlFor="message" className="text-white">Message *</label>
        <input type="text" name="message" id="message" placeholder="Ecrire message" required/>
      </div>
      <div className="flex flex-row gap-4">
        <label htmlFor="file" className="text-white">Image (optionnelle)</label>
        <input type="file" name="file" id="file" accept="image/*"/>
      </div>
      <button className="text-white">Envoyer</button>
      {state?.error && <p className="text-red-500">{state.error} !</p>}
    </form>
  )
}