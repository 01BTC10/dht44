import { Routes, Route, Navigate } from "react-router-dom";

import SiteShell      from "./components/SiteShell";
import DashboardShell from "./components/DashboardShell";

import Home         from "./pages/Home";
import About        from "./pages/About";
import Privacy      from "./pages/Privacy";
import ProtocolHub  from "./pages/ProtocolHub";
import LibLanding   from "./pages/LibLanding";
import BlogIndex    from "./pages/BlogIndex";
import NotFound     from "./pages/NotFound";

import {
  Kademlia, Bep5, Bep44 as Bep44Article, Bep51,
  LibQuickstart, LibApi, LibPersistence,
  BlogDhtSize, BlogClassifyingPeers, BlogEmbedDht, BlogKademliaVsChord,
} from "./pages/articles";

/* Existing dashboard tab pages — content unchanged. */
import Peers      from "./pages/Peers";
import Queries    from "./pages/Queries";
import Infohashes from "./pages/Infohashes";
import Bep44Tab   from "./pages/Bep44";
import Graph      from "./pages/Graph";

export default function App() {
  return (
    <Routes>
      <Route element={<SiteShell />}>
        <Route path="/"               element={<Home />} />
        <Route path="/about"          element={<About />} />
        <Route path="/privacy"        element={<Privacy />} />

        <Route path="/protocol"           element={<ProtocolHub />} />
        <Route path="/protocol/kademlia"  element={<Kademlia />} />
        <Route path="/protocol/bep5"      element={<Bep5 />} />
        <Route path="/protocol/bep44"     element={<Bep44Article />} />
        <Route path="/protocol/bep51"     element={<Bep51 />} />

        <Route path="/lib"              element={<LibLanding />} />
        <Route path="/lib/quickstart"   element={<LibQuickstart />} />
        <Route path="/lib/api"          element={<LibApi />} />
        <Route path="/lib/persistence"  element={<LibPersistence />} />

        <Route path="/blog"                       element={<BlogIndex />} />
        <Route path="/blog/dht-size"              element={<BlogDhtSize />} />
        <Route path="/blog/classifying-peers"     element={<BlogClassifyingPeers />} />
        <Route path="/blog/embed-dht-c-app"       element={<BlogEmbedDht />} />
        <Route path="/blog/kademlia-vs-chord"     element={<BlogKademliaVsChord />} />
      </Route>

      <Route path="/dashboard" element={<DashboardShell />}>
        <Route index                element={<Navigate to="peers" replace />} />
        <Route path="peers"         element={<Peers />} />
        <Route path="queries"       element={<Queries />} />
        <Route path="infohashes"    element={<Infohashes />} />
        <Route path="bep44"         element={<Bep44Tab />} />
        <Route path="graph"         element={<Graph />} />
      </Route>

      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}
