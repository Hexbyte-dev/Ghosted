export default function Landing() {
  const handleSignIn = () => {
    window.location.href = `${import.meta.env.VITE_API_URL || 'http://localhost:3001'}/auth/google`;
  };

  return (
    <div className="landing">
      <div className="landing-hero">
        <h1>Ghosted</h1>
        <p className="tagline">Ghost your subscriptions.</p>
        <p className="description">
          Tired of spam? Ghosted scans your Gmail, finds every subscription,
          and lets you mass-unsubscribe with one click. Your old emails get
          archived, not deleted.
        </p>
        <button className="btn-primary" onClick={handleSignIn}>
          Sign in with Google
        </button>
      </div>
    </div>
  );
}
