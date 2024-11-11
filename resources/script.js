function filterItems() {
  const env = document.getElementById("env").value.toLowerCase();
  const active = document.getElementById("active").value;
  const search = document.getElementById("search").value.toLowerCase();
  const tiles = document.querySelectorAll(".tile");
  let visibleCount = 0;

  tiles.forEach((tile) => {
    const tileEnv = tile.dataset.env.toLowerCase();
    const tileActive = tile.dataset.active;
    const tileName = tile.dataset.name.toLowerCase();

    const matchesEnv = !env || tileEnv === env;
    const matchesActive = !active || tileActive === active;
    const matchesSearch = !search || tileName.includes(search);

    const isVisible = matchesEnv && matchesActive && matchesSearch;
    tile.hidden = !isVisible;

    if (isVisible) visibleCount++;
  });

  // Show/hide no results message
  document.querySelector(".no-results").style.display =
    visibleCount === 0 ? "block" : "none";
}
