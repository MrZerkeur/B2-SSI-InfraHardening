import { redirect } from "next/navigation";
import { getSession, getAllContactForms, ContactForm } from "../actions";
import Image from "next/image";

export default async function Admin() {
  const session = await getSession();

  if (!session.isLoggedIn || !session.isAdmin) {
    redirect('/not-found');
  }

  const contactForms = await getAllContactForms();
  
  return (
    <>
      <main className="flex min-h-screen flex-col items-center p-4 gap-32">
        <h1 className='text-5xl'>Bien joué tu es chez l&#39;admin</h1>
        {contactForms && 
        <div className="relative overflow-x-auto">
          <table className="w-full text-sm text-left rtl:text-right text-gray-500 dark:text-gray-400">
            <thead className="text-xs text-gray-700 uppercase bg-gray-50 dark:bg-gray-700 dark:text-gray-400">
              <tr>
                <th scope="col" className="px-6 py-3">
                  Prénom
                </th>
                <th scope="col" className="px-6 py-3">
                  Nom
                </th>
                <th scope="col" className="px-6 py-3">
                  Adresse mail
                </th>
                <th scope="col" className="px-6 py-3">
                  Message
                </th>
                <th scope="col" className="px-6 py-3">
                  Téléphone
                </th>
                <th scope="col" className="px-6 py-3">
                  Lien du fichier
                </th>
              </tr>
            </thead>
            <tbody>
              {contactForms.map((contactForm, index) => (
                <tr key={index} className="bg-white border-b dark:bg-gray-800 dark:border-gray-700">
                  <th scope="row" className="px-6 py-4 font-medium text-gray-900 whitespace-nowrap dark:text-white">
                    {contactForm.firstName}
                  </th>
                  <td className="px-6 py-4">
                    {contactForm.lastName}
                  </td>
                  <td className="px-6 py-4">
                    {contactForm.email}
                  </td>
                  <td className="px-6 py-4">
                    {contactForm.message}
                  </td>
                  <td className="px-6 py-4">
                    {contactForm.tel}
                  </td>
                  <td className="px-6 py-4">
                    {contactForm.filePath}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        }
      </main>
    </>
  )
}
