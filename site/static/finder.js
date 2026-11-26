const field = document.querySelector("#guide-query");
const sections = document.querySelectorAll(".guide-section");
const results = document.querySelector("#results");

function filterGuides() {
  const query = field.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  let total = 0;
  for (const section of sections) {
    let visible = 0;
    for (const card of section.querySelectorAll(".guide-card")) {
      const text = (card.textContent + " " + card.dataset.topics).toLowerCase();
      card.hidden = !query.every(word => text.includes(word));
      if (!card.hidden) visible++;
    }
    section.hidden = visible === 0;
    total += visible;
  }
  results.textContent = query.length === 0 ? "" : total === 0
    ? "No matching guides. Try a service such as history or an action such as browse."
    : total + (total === 1 ? " matching guide." : " matching guides.");
}

document.querySelector(".finder").hidden = false;
field.addEventListener("input", filterGuides);
filterGuides();
