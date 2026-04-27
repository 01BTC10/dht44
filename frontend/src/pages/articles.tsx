/*
 * Article page index. Each entry re-exports the actual article component
 * from src/pages/articles/<Name>.tsx. Routes in App.tsx import these by
 * name, so adding/removing an article is a single line here plus the
 * underlying component file.
 */

/* ===== /protocol/* ===== */
export { default as Kademlia } from "./articles/Kademlia";
export { default as Bep5     } from "./articles/Bep5";
export { default as Bep44    } from "./articles/Bep44";
export { default as Bep51    } from "./articles/Bep51";

/* ===== /lib/* ===== */
export { default as LibQuickstart   } from "./articles/LibQuickstart";
export { default as LibApi          } from "./articles/LibApi";
export { default as LibPersistence  } from "./articles/LibPersistence";

/* ===== /blog/* ===== */
export { default as BlogDhtSize           } from "./articles/BlogDhtSize";
export { default as BlogClassifyingPeers  } from "./articles/BlogClassifyingPeers";
export { default as BlogEmbedDht          } from "./articles/BlogEmbedDht";
export { default as BlogKademliaVsChord   } from "./articles/BlogKademliaVsChord";
