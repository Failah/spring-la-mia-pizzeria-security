package com.example.demo.api.controller;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.model.Pizza;
import com.example.demo.repository.PizzaRepository;

@RestController
@CrossOrigin
@RequestMapping("/api/pizzas")
public class PizzaControllerApi {

	@Autowired
	PizzaRepository pizzaRepository;

	@GetMapping
	public List<Pizza> index(@RequestParam(required = false) String name) {
		if (name != null && !name.isBlank()) {
			return pizzaRepository.findByNameContainingIgnoreCase(name);
		} else {
			return pizzaRepository.findAll();
		}
	}

	@GetMapping("/{id}")
	public ResponseEntity<Pizza> show(@PathVariable("id") Integer id) {
		Optional<Pizza> result = pizzaRepository.findById(id);
		if (result.isPresent())
			return new ResponseEntity<Pizza>(result.get(), HttpStatus.OK);
		else
			return new ResponseEntity<Pizza>(HttpStatus.NOT_FOUND);
	}

//	@GetMapping("/{id}")
//	public ResponseEntity<Pizza> show(@PathVariable("id") Integer id) {
//		Pizza pizza = pizzaRepository.getReferenceById(id);
//		if (pizza != null)
//			return new ResponseEntity<Pizza>(pizza, HttpStatus.OK);
//		else
//			return new ResponseEntity<Pizza>(HttpStatus.NOT_FOUND);
//	}

	@PostMapping("/create")
	public Pizza create(@RequestBody Pizza pizza) {
		return pizzaRepository.save(pizza);
	}

	@PutMapping("edit/{id}")
	public Pizza update(@RequestBody Pizza pizza, @PathVariable("id") Integer id) {
		Pizza b = pizzaRepository.getReferenceById(id);
		b.setName(pizza.getName());
		b.setPrice(pizza.getPrice());
		return pizzaRepository.save(b);
	}

	@DeleteMapping("delete/{id}")
	public void delete(@PathVariable("id") Integer id) {
		pizzaRepository.deleteById(id);
	}
}
