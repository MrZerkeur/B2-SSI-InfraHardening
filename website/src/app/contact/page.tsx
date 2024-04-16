import ContactForm from "@/components/Forms/ContactForm";

export default function Home() {
  return (
    <>
      <main className="flex min-h-screen flex-col items-center p-4 gap-32">
        <h1 className='text-5xl'>Contact</h1>
        <ContactForm/>
      </main>
    </>
    
  )
}
