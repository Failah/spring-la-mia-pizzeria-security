package com.example.demo.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.demo.model.Pizza;

public interface PizzaRepository extends JpaRepository<Pizza, Integer> {

	public List<Pizza> findByNameContainingIgnoreCase(String name);

}
