import { Link } from "react-router-dom";
import SEO from "../components/SEO";

export default function NotFound() {
  return (
    <>
      <SEO
        title="Not found — dht44"
        description="The requested page does not exist."
        path="/404"
        noindex
      />
      <section className="not-found">
        <h1>404</h1>
        <p>That URL doesn't exist on dht44.com.</p>
        <p>
          Try the <Link to="/">home page</Link>, the{" "}
          <Link to="/protocol">protocol reference</Link>, or the{" "}
          <Link to="/dashboard/peers">live dashboard</Link>.
        </p>
      </section>
    </>
  );
}
