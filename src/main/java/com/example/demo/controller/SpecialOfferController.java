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
import org.springframework.web.bind.annotation.RequestParam;

import com.example.demo.model.Pizza;
import com.example.demo.model.SpecialOffer;
import com.example.demo.repository.PizzaRepository;
import com.example.demo.repository.SpecialOfferRepository;

import jakarta.persistence.EntityNotFoundException;
import jakarta.validation.Valid;

@Controller
@RequestMapping("/special-offers")
public class SpecialOfferController {

	@Autowired
	private SpecialOfferRepository specialOfferRepository;

	@Autowired
	private PizzaRepository pizzaRepository;

	@GetMapping()
	public String index(Model model) {
		List<SpecialOffer> specialOffers = specialOfferRepository.findAll();
		model.addAttribute("specialOffers", specialOffers);

		return "special-offers/index";
	}

	@GetMapping("/create")
	public String create(@RequestParam(name = "pizzaId", required = true) Integer pizzaId, Model model)
			throws Exception {

		SpecialOffer specialOffer = new SpecialOffer();

		try {
			Pizza pizza = pizzaRepository.getReferenceById(pizzaId);
			specialOffer.setPizza(pizza);
		} catch (EntityNotFoundException e) {
			throw new Exception("This pizza does not exist. Id=" + pizzaId);
		}

		model.addAttribute("pizzaId", pizzaId);
		model.addAttribute("specialOffer", specialOffer);

		return "special-offers/create";
	}

	@PostMapping("/store")
	public String store(@Valid @ModelAttribute("specialOffer") SpecialOffer formSpecialOffer,
			BindingResult bindingResult, Model model, @RequestParam("pizzaId") String name) {
		System.out.println();
		if (bindingResult.hasErrors())
			return "special-offers/create";

		Integer pizzaId = (int) Long.parseLong(name);
		Pizza pizza = pizzaRepository.getReferenceById(pizzaId);

		formSpecialOffer.setPizza(pizza);

		specialOfferRepository.save(formSpecialOffer);

		return "redirect:/pizzas/" + pizzaId;
	}

	@GetMapping("/edit/{id}")
	public String edit(@PathVariable("id") Long id, Model model) {
		SpecialOffer specialOffer = specialOfferRepository.getReferenceById(id);
		if (specialOffer == null) {
			throw new RuntimeException("SpecialOffer not found");
		}
		model.addAttribute("specialOffer", specialOffer);
		return "special-offers/edit";
	}

	@PostMapping("/update")
	public String update(@RequestParam("pizzaId") String name,
			@ModelAttribute("specialOffer") SpecialOffer specialOffer) {

		Integer pizzaId = (int) Long.parseLong(name);
		Pizza pizza = pizzaRepository.getReferenceById(pizzaId);

		specialOffer.setPizza(pizza);

		specialOfferRepository.save(specialOffer);

		return "redirect:/pizzas/" + pizzaId;
	}

	@PostMapping("/delete/{id}")
	public String delete(@PathVariable("id") Long id) {
		specialOfferRepository.deleteById(id);
		return "redirect:/special-offers";
	}

	// redirectAttributes.addAttribute("id", pizzaId);
	// @RequestParam(name = "pizzaId", required = true) Integer pizzaId,
	// RedirectAttributes redirectAttributes

}
