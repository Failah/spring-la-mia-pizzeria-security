package com.example.demo.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.example.demo.model.Ingredient;
import com.example.demo.repository.IngredientRepository;

import jakarta.validation.Valid;

@Controller
@RequestMapping("/ingredients")
public class IngredientController {
	@Autowired
	private IngredientRepository ingredientRepository;

	@GetMapping
	public String index(Model model) {
		List<Ingredient> ingredients = ingredientRepository.findAll();
		model.addAttribute("ingredients", ingredients);
		return "ingredients/indexIngredients";
	}

	@GetMapping("/create")
	public String create(Model model) {
		Ingredient ingredient = new Ingredient();
		model.addAttribute("ingredient", ingredient);
		return "ingredients/createIngredient";
	}

	@PostMapping("/create")
	public String store(@Valid @ModelAttribute("ingredient") Ingredient ingredientForm, BindingResult bindingResult,
			Model model) {

		if (bindingResult.hasErrors()) {
			return "ingredients/createIngredient";
		}

		ingredientRepository.save(ingredientForm);
		return "redirect:/ingredients";
	}

	@GetMapping("/edit/{id}")
	public String edit(@PathVariable("id") Integer id, Model model) {
		Ingredient ingredient = ingredientRepository.getReferenceById(id);
		model.addAttribute("ingredient", ingredient);
		return "ingredients/editIngredient";
	}

	@PostMapping("/edit/{id}")
	public String update(@Valid @ModelAttribute("ingredient") Ingredient ingredientForm, BindingResult bindingResult,
			Model model) {
		if (bindingResult.hasErrors()) {
			return "ingredients/editIngredient";
		}
		ingredientRepository.save(ingredientForm);
		return "redirect:/ingredients";
	}

	@PostMapping("/delete/{id}")
	public String delete(@PathVariable("id") Integer id) {
		ingredientRepository.deleteById(id);
		return "redirect:/ingredients";
	}
}
