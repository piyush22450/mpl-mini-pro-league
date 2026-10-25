document.addEventListener("DOMContentLoaded", () => {
  const selector = document.getElementById("player_count");
  const container = document.getElementById("players");
  if (!selector || !container) return;
  function renderRoster() {
    const total = Number(selector.value);
    container.innerHTML = Array.from({ length: total }, (_, i) => {
      const type = i < 11 ? `Playing player ${i + 1}` : `Substitute ${i - 10}`;
      return `<fieldset class="player">
        <legend>${type}</legend>
        <label>Full name<input name="player_name" maxlength="100" required></label>
        <label>Date of birth<input type="date" name="dob" required max="${new Date().toISOString().slice(0,10)}"></label>
      </fieldset>`;
    }).join("");
  }
  selector.addEventListener("change", renderRoster);
  renderRoster();
});