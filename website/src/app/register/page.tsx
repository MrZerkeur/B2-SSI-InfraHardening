import RegisterForm from "@/components/Forms/RegisterForm"

export default function Register() {
  return (
    <>
      <main className="flex gap-4 min-h-screen flex-col items-center p-4">
        <h1 className='text-5xl'>Register</h1>
        <RegisterForm/>
      </main>
    </>
  )
}
