import tkinter as tk
from tkinter import font

class RestaurantScroller(tk.Tk):
    def __init__(self, restaurants):
        super().__init__()
        self.title("Restaurant Scroller")
        self.geometry("300x400")

        self.restaurants = restaurants
        self.selected_index = 2  # Start with the middle restaurant selected

        # Configure fonts
        self.normal_font = font.Font(size=12)
        self.highlight_font = font.Font(size=16, weight="bold")
        self.faded_font = font.Font(size=10)

        # Create a canvas for the scroller
        self.canvas = tk.Canvas(self, bg="white", highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)

        # Draw the initial scroller
        self.draw_scroller()

        # Bind arrow keys for scrolling
        self.bind("<Up>", self.scroll_up)
        self.bind("<Down>", self.scroll_down)

    def draw_scroller(self):
        self.canvas.delete("all")  # Clear the canvas

        # Draw restaurants with appropriate styling
        for i in range(-2, 3):  # Display 5 restaurants at a time
            index = self.selected_index + i
            if 0 <= index < len(self.restaurants):
                restaurant = self.restaurants[index]
                y = 150 + i * 50  # Vertical position

                if i == 0:
                    # Highlight the middle restaurant
                    self.canvas.create_text(150, y, text=restaurant, font=self.highlight_font, fill="black")
                else:
                    # Fade the top and bottom restaurants
                    self.canvas.create_text(150, y, text=restaurant, font=self.faded_font, fill="gray")

    def scroll_up(self, event):
        if self.selected_index > 0:
            self.selected_index -= 1
            self.draw_scroller()

    def scroll_down(self, event):
        if self.selected_index < len(self.restaurants) - 1:
            self.selected_index += 1
            self.draw_scroller()

if __name__ == "__main__":
    # Sample list of restaurants
    restaurants = [
        "Wildfire",
        "Volk - Streeterville",
        "XOCO",
        "Andy's Jazz Club & Restaurant",
        "avec Restaurant",
        "Morton's The Steakhouse",
        "The Cheesecake Factory",
        "Pizzeria Uno",
        "Giordano's",
        "Lou Malnati's"
    ]

    # Run the scroller
    app = RestaurantScroller(restaurants)
    app.mainloop()